"""Isolated local archive. Workers must verify committed rows before finalizing."""
from datetime import datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
import time
from contextlib import contextmanager

from .db import transaction


class ArchiveUnavailable(RuntimeError):
    pass


class ArchiveConflict(ValueError):
    pass


class ArchiveDenied(PermissionError):
    pass


GENESIS = "0" * 64
MAX_BYTES = 8192
MAX_RECORDS = 1024
MAX_PROJECTIONS = 8
KINDS = frozenset({
    "access_decision", "evidence_access", "enrolment", "revocation", "role_change",
    "grant_change", "approval_issue", "approval_consume", "rotation", "backup_verify",
    "restore", "trust_change", "archive_control", "detector_source", "detector_alert",
    "resource_create",
})


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def fields(value, names):
    if type(value) is not dict or set(value) != set(names.split()):
        raise ValueError("unexpected archive fields")


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:@-]{1,128}", value):
        raise ValueError("invalid archive identifier")


def digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("invalid digest")


def integer(value):
    if type(value) is not int or not 0 <= value <= 2**63 - 1:
        raise ValueError("invalid archive integer")


STATE_MUTATIONS = frozenset({
    "enrolment", "revocation", "role_change", "grant_change", "approval_issue",
    "approval_consume", "rotation", "restore", "trust_change", "resource_create",
})
CREATION_KINDS = {"enrolment": "credential", "resource_create": "asset", "approval_issue": "approval"}
TELEMETRY_KINDS = {"detector_source", "detector_alert"}
MAX_INITIAL_PROJECTIONS = 1024


def event_schema(value):
    if type(value) is not dict or not isinstance(value.get("kind"), str):
        raise ValueError("invalid event")
    kind = value["kind"]
    names = "version event_id request_id actor node subsystem kind entity_id authorization reason received_ms source_ids"
    rotation = kind == "rotation" and value.get("authorization") == "allow"
    fields(value, names + (" approval_id" if rotation else "") + (" timing" if kind in TELEMETRY_KINDS else "")
           + (" credential_id" if "credential_id" in value else "")
           + (" resource_present" if kind == "access_decision" and "resource_present" in value else "")
           + (" detector_context" if kind in TELEMETRY_KINDS and "detector_context" in value else "")
           + (" rule_id rule_version approval_ref" if kind == "detector_alert" else ""))
    if type(value["version"]) is not int or value["version"] != 2 or kind not in KINDS:
        raise ValueError("unsupported event schema or kind")
    for name in ("event_id", "request_id", "actor", "node", "subsystem", "entity_id", "reason"):
        identifier(value[name])
    if "credential_id" in value:
        identifier(value["credential_id"])
    if value["authorization"] not in ("allow", "deny", "observed", "unavailable"):
        raise ValueError("invalid event result")
    if "resource_present" in value and (
        type(value["resource_present"]) is not bool
        or (not value["resource_present"] and value["authorization"] != "deny")
    ):
        raise ValueError("invalid access resource state")
    if rotation:
        identifier(value["approval_id"])
        if value["reason"] not in {"approved", "version_rotated"}:
            raise ValueError("authorized rotation requires a valid approval decision")
    creation_reasons = {"authorized", "enrolled"} if kind == "enrolment" else {"authorized"}
    if kind in CREATION_KINDS and value["authorization"] == "allow" and value["reason"] not in creation_reasons:
        raise ValueError("creation requires an authorized decision")
    integer(value["received_ms"])
    sources = value["source_ids"]
    if type(sources) is not list or len(sources) > 32 or bool(sources) != (kind == "detector_alert"):
        raise ValueError("invalid evidence references")
    refs = []
    for source in sources:
        fields(source, "producer event_id")
        identifier(source["producer"])
        identifier(source["event_id"])
        refs.append((source["producer"], source["event_id"]))
    if len(set(refs)) != len(refs):
        raise ValueError("duplicate evidence reference")
    if kind in TELEMETRY_KINDS:
        timing = value["timing"]
        fields(timing, "corrected_ms uncertainty_ms")
        integer(timing["corrected_ms"])
        integer(timing["uncertainty_ms"])
    if "detector_context" in value:
        context = value["detector_context"]
        if type(context) is not dict:
            raise ValueError("invalid detector context")
        if kind == "detector_source":
            fields(context, "event_ms received_ms event_time_utc received_time_utc clock_offset_ms action outcome role role_before source_service target_service session_id correlation_id approval_id requested_scope")
            for name in ("event_ms", "received_ms"):
                integer(context[name])
            for name in ("event_time_utc", "received_time_utc"):
                stamp = context[name]
                if not isinstance(stamp, str) or len(stamp) > 40 or datetime.fromisoformat(stamp).tzinfo is None:
                    raise ValueError("invalid detector timestamp")
            offset = context["clock_offset_ms"]
            if type(offset) is not int or abs(offset) > 86_400_000:
                raise ValueError("invalid detector clock offset")
            for name in ("action", "outcome", "role", "source_service", "target_service",
                         "session_id", "correlation_id"):
                identifier(context[name])
            scope = context["requested_scope"]
            if type(scope) is not list or len(scope) > 32:
                raise ValueError("invalid requested detector scope")
            for service in scope:
                identifier(service)
            for name in ("approval_id", "role_before"):
                if context[name] is not None:
                    identifier(context[name])
        else:
            fields(context, "classification approval_status approval_digest approval")
            if context["classification"] not in ("policy_violation", "investigate"):
                raise ValueError("invalid detector classification")
            if context["approval_status"] not in ("missing", "matches", "mismatch", "outside_scope"):
                raise ValueError("invalid detector approval status")
            approval = context["approval"]
            proof = context["approval_digest"]
            if approval is None:
                if proof is not None or context["approval_status"] != "missing":
                    raise ValueError("invalid missing approval context")
            else:
                fields(approval, "approval_id subject operation role scope valid_from_utc valid_until_utc")
                for name in ("approval_id", "subject", "operation", "role"):
                    identifier(approval[name])
                for name in ("valid_from_utc", "valid_until_utc"):
                    stamp = approval[name]
                    if not isinstance(stamp, str) or len(stamp) > 40 or datetime.fromisoformat(stamp).tzinfo is None:
                        raise ValueError("invalid detector approval timestamp")
                scope = approval["scope"]
                if type(scope) is not list or len(scope) > 32:
                    raise ValueError("invalid detector approval scope")
                for service in scope:
                    identifier(service)
                if (proof != hashlib.sha256(canonical(approval)).hexdigest()
                        or approval["approval_id"] != value["approval_ref"]
                        or context["approval_status"] == "missing"):
                    raise ValueError("invalid detector approval provenance")
    if kind == "detector_alert":
        identifier(value["rule_id"])
        integer(value["rule_version"])
        if value["rule_version"] == 0:
            raise ValueError("invalid rule version")
        if value["approval_ref"] is not None:
            identifier(value["approval_ref"])


def projection_schema(projection, *, maximum=MAX_PROJECTIONS):
    fields(projection, "schema entities")
    if type(projection["schema"]) is not int or projection["schema"] != 1:
        raise ValueError("invalid projection version")
    entities = projection["entities"]
    if not isinstance(entities, list) or len(entities) > maximum:
        raise ValueError("invalid projection size")
    keys = []
    for entity in entities:
        credential = type(entity) is dict and entity.get("kind") == "credential"
        fields(entity, "kind id version digest" + (" status" if credential else ""))
        identifier(entity["kind"])
        identifier(entity["id"])
        integer(entity["version"])
        digest(entity["digest"])
        if (entity["version"] == 0) != (entity["digest"] == GENESIS):
            raise ValueError("absent state must use version zero and the zero digest")
        if credential and (entity["status"] not in ("absent", "active", "revoked")
                           or (entity["status"] == "absent") != (entity["version"] == 0)):
            raise ValueError("invalid credential status")
        keys.append((entity["kind"], entity["id"]))
    if keys != sorted(set(keys)):
        raise ValueError("projections must be uniquely identified and ordered")
    return keys


def outcome_schema(outcome, pending):
    fields(outcome, "basis before after delivery")
    if (outcome["basis"] not in ("verified_commit", "verified_noncommit")
            or outcome["delivery"] not in ("unknown", "withheld")):
        raise ValueError("invalid transaction or delivery outcome")
    before, after = outcome["before"], outcome["after"]
    if projection_schema(before) != projection_schema(after):
        raise ArchiveConflict("outcome changed the covered entities")
    if before != pending["expected"]:
        raise ArchiveConflict("outcome pre-state disagrees with intent")
    event = pending["event"]
    kind = event["kind"]
    changes = list(zip(before["entities"], after["entities"]))
    for old, new in changes:
        if old["kind"] != "credential" or old == new:
            continue
        if old["status"] == "revoked" and new["status"] != "revoked":
            raise ValueError("revoked credential cannot change status")
        if (kind not in {"revocation", "enrolment", "role_change"}
                or old["id"] != event["entity_id"]):
            raise ValueError("operation cannot change this credential")
    if outcome["basis"] == "verified_noncommit":
        if before != after or outcome["delivery"] != "withheld":
            raise ValueError("abort must leave state unchanged and withhold response data")
    elif event["authorization"] == "allow" and event["kind"] in STATE_MUTATIONS:
        if kind == "revocation":
            old, new = next((old, new) for old, new in changes
                            if (old["kind"], old["id"]) == ("credential", event["entity_id"]))
            if old["status"] == "revoked" or event["reason"] == "already_revoked":
                if old["status"] != "revoked" or before != after:
                    raise ValueError("idempotent revocation requires unchanged revoked state")
            elif (old["status"] != "active" or new["status"] != "revoked"
                  or new["version"] != old["version"] + 1 or old["digest"] == new["digest"]):
                raise ValueError("revocation must transition active state to revoked")
        elif kind in CREATION_KINDS:
            target = CREATION_KINDS[kind], event["entity_id"]
            old, new = next((old, new) for old, new in changes if (old["kind"], old["id"]) == target)
            if old["version"] != 0 or new["version"] != 1:
                raise ValueError("creation must transition from absent to version one")
            if kind == "enrolment" and new["status"] != "active":
                raise ValueError("enrolment must establish an active credential")
        elif kind == "rotation":
            for old, new in changes:
                if old["kind"] == "credential":
                    continue
                if old["version"] == 0 or old["digest"] == new["digest"]:
                    raise ValueError("rotation requires existing state and new content")
                if old["kind"] == "asset" and new["version"] != old["version"] + 1:
                    raise ValueError("rotation must advance the asset by one version")
                if old["kind"] == "approval" and new["version"] != 0:
                    raise ValueError("rotation must consume its bound approval")
        elif kind == "role_change":
            old, new = next((old, new) for old, new in changes
                            if (old["kind"], old["id"]) == ("credential", event["entity_id"]))
            if (old["status"] != new["status"] or old["status"] == "absent"
                    or new["version"] != old["version"] + 1 or old["digest"] == new["digest"]):
                raise ValueError("role change must preserve credential lifecycle")
        else:
            raise ValueError("unsupported state transition")
    elif before != after:
        raise ValueError("non-mutation or denied intent cannot change projected state")


def producer_allows(grant, record):
    return (record["producer"] == grant["principal"] and record["node"] == grant["node"]
            and record["subsystem"] == grant["subsystem"] and record["event"]["kind"] in grant["scopes"])


def intent_projection(event, expected):
    entries = {(row["kind"], row["id"]): row for row in expected["entities"]}
    keys = set(entries)
    kind, target = event["kind"], event["entity_id"]
    allowed = event["authorization"] == "allow"
    caller = {("credential", event["credential_id"])} if "credential_id" in event else set()
    if caller and (not caller <= keys or (allowed and entries[next(iter(caller))]["status"] != "active")):
        raise ValueError("intent must bind the authenticated credential")
    if kind in TELEMETRY_KINDS:
        required = set()
    elif kind == "access_decision":
        if "resource_present" not in event and event["authorization"] == "deny" and event["reason"] == "unknown_resource":
            required = caller
        else:
            required = caller | {("asset", target), ("grant", target)}
            if allowed and not caller:
                raise ValueError("protected access requires an authenticated credential")
    elif kind == "evidence_access":
        if allowed and not caller:
            raise ValueError("evidence access requires an authenticated credential")
        required = caller
    elif kind == "rotation":
        required = caller | {("asset", target)}
        if allowed:
            required.add(("approval", event["approval_id"]))
            if not required <= keys or any(entries[key]["version"] == 0 for key in required):
                raise ValueError("rotation must bind a live asset and approval")
        else:
            # A denied rotation may bind the approval evaluated by the application.
            approvals = {key for key in keys if key[0] == "approval"}
            if len(approvals) > 1:
                raise ValueError("rotation covers multiple approvals")
            required |= approvals
    elif kind in {"revocation", "role_change"}:
        required = caller | {("credential", target)}
        if kind == "revocation" and allowed and event["reason"] not in ("revoked", "already_revoked"):
            raise ValueError("unsupported revocation decision")
    elif kind in CREATION_KINDS:
        required = caller | ({(CREATION_KINDS[kind], target)} if allowed else set())
        if allowed and entries.get((CREATION_KINDS[kind], target), {}).get("version") != 0:
            raise ValueError("creation must bind an absent entity")
    else:
        raise ValueError("unsupported archive operation")
    if keys != required:
        raise ValueError("intent must cover its required entity types")
    if kind == "access_decision" and any(
        (entries[key]["version"] != 0) != event.get("resource_present", True)
        for key in required - caller
    ):
        raise ValueError("access must bind matching asset and grant presence")



def decode_event(raw):
    """Accept only the canonical wire representation, including unique keys."""
    if type(raw) is not bytes or len(raw) > MAX_BYTES:
        raise ValueError("invalid event size")
    try:
        event = json.loads(raw.decode("ascii"))
        event_schema(event)
        if canonical(event) != raw:
            raise ValueError("event is not canonical")
    except (UnicodeError, TypeError, RecursionError) as error:
        raise ValueError("invalid event") from error
    return event


class Archive:
    def __init__(self, path, store_id, *, receipt_key, grant_key):
        identifier(store_id)
        if (type(receipt_key) is not bytes or type(grant_key) is not bytes
                or len(receipt_key) != 32 or len(grant_key) != 32
                or hmac.compare_digest(receipt_key, grant_key)):
            raise ValueError("independent 32-byte archive keys required")
        self.path = Path(path).resolve()
        self.store_id = store_id
        self.receipt_key = receipt_key
        self.grant_key = grant_key

    def mac(self, key, domain, value):
        return hmac.digest(key, domain + b"\0" + canonical([self.store_id, value]), "sha256").hex()

    def provision(self, grants, *, initial):
        """Create a new archive exclusively. Never run from a request path."""
        projection_schema(initial, maximum=MAX_INITIAL_PROJECTIONS)
        if not initial["entities"] or any(entity["version"] == 0 for entity in initial["entities"]):
            raise ValueError("initial projection requires the existing entities")
        prepared = []
        bindings = {}
        for token, grant in grants.items():
            token_digest = self.token_digest(token)
            if grant.get("role") == "producer":
                fields(grant, "principal role scopes expires_ms revoked node subsystem")
                identifier(grant["node"])
                identifier(grant["subsystem"])
                binding = grant["node"], grant["subsystem"]
                if bindings.setdefault(grant["principal"], binding) != binding:
                    raise ValueError("producer identity has inconsistent bindings")
            else:
                fields(grant, "principal role scopes expires_ms revoked")
            identifier(grant["principal"])
            if grant["role"] not in ("producer", "investigator") or type(grant["revoked"]) is not bool:
                raise ValueError("invalid role or status")
            integer(grant["expires_ms"])
            scopes = grant["scopes"]
            if not isinstance(scopes, list) or not scopes or len(scopes) > 32:
                raise ValueError("explicit scopes required")
            for scope in scopes:
                if scope not in KINDS:
                    raise ValueError("unknown archive scope")
            data = canonical(grant)
            prepared.append((token_digest, data, self.mac(
                self.grant_key, b"archive-grant-v1", [token_digest, grant])))
        fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        with transaction(self.path) as db:
            db.execute("CREATE TABLE head(singleton INTEGER PRIMARY KEY CHECK(singleton=1), seq INTEGER, tag TEXT, proof TEXT)")
            db.execute("CREATE TABLE initial(singleton INTEGER PRIMARY KEY CHECK(singleton=1), body BLOB, proof TEXT)")
            db.execute("INSERT INTO initial VALUES(1,?,?)", (
                canonical(initial), self.mac(self.receipt_key, b"archive-initial-v1", initial)))
            db.execute("CREATE TABLE records(seq INTEGER PRIMARY KEY, body BLOB, tag TEXT)")
            db.execute("CREATE TABLE grants(digest TEXT PRIMARY KEY, body BLOB, proof TEXT)")
            db.execute("CREATE TABLE recovery_grants(digest TEXT PRIMARY KEY, body BLOB, proof TEXT)")
            db.executemany("INSERT INTO grants VALUES(?,?,?)", prepared)
            db.execute("INSERT INTO head VALUES(1,0,?,?)", (GENESIS, self.head_proof(0, GENESIS)))
        directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def head_proof(self, sequence, tag):
        return self.mac(self.receipt_key, b"archive-head-v1", [sequence, tag])

    @staticmethod
    def token_digest(token):
        if not isinstance(token, str) or not 32 <= len(token) <= 256 or not token.isascii():
            raise ArchiveDenied("invalid archive credential")
        return hashlib.sha256(token.encode("ascii")).hexdigest()

    def authorize(self, db, token, role):
        hashed = self.token_digest(token)
        row = db.execute("SELECT body,proof FROM grants WHERE digest=?", (hashed,)).fetchone()
        if row is None:
            raise ArchiveDenied("unknown archive credential")
        body, proof = row
        grant = json.loads(body)
        if not hmac.compare_digest(proof, self.mac(self.grant_key, b"archive-grant-v1", [hashed, grant])):
            raise ArchiveUnavailable("invalid archive grant")
        if grant["role"] != role or grant["revoked"] or grant["expires_ms"] <= self.now():
            raise ArchiveDenied("archive credential not authorized")
        return grant

    @staticmethod
    def now():
        return time.time_ns() // 1_000_000

    @contextmanager
    def verified(self, *, write):
        mode = "rw" if write else "ro"
        try:
            with transaction(self.path.as_uri() + f"?mode={mode}", write=write, uri=True) as db:
                head = db.execute("SELECT seq,tag,proof FROM head WHERE singleton=1").fetchone()
                if head is None or not hmac.compare_digest(head[2], self.head_proof(head[0], head[1])):
                    raise ArchiveUnavailable("invalid archive position")
                row = db.execute("SELECT body,proof FROM initial WHERE singleton=1").fetchone()
                if row is None:
                    raise ArchiveUnavailable("missing initial projection")
                initial = json.loads(row[0])
                projection_schema(initial, maximum=MAX_INITIAL_PROJECTIONS)
                if row[0] != canonical(initial) or not hmac.compare_digest(
                    row[1], self.mac(self.receipt_key, b"archive-initial-v1", initial)
                ):
                    raise ArchiveUnavailable("invalid initial projection")
                records = []
                previous = GENESIS
                for seq, raw, tag in db.execute("SELECT seq,body,tag FROM records ORDER BY seq"):
                    if len(records) >= MAX_RECORDS or type(raw) is not bytes or len(raw) > MAX_BYTES * 2:
                        raise ArchiveUnavailable("archive record exceeds limits")
                    body = json.loads(raw)
                    if (seq != len(records) + 1 or body["sequence"] != seq
                            or body["predecessor"] != previous or raw != canonical(body)
                            or not hmac.compare_digest(tag, self.mac(self.receipt_key, b"archive-record-v1", body))):
                        raise ArchiveUnavailable("broken archive chain")
                    records.append({**body, "tag": tag})
                    previous = tag
                if head[:2] != (len(records), previous):
                    raise ArchiveUnavailable("archive position disagrees with history")
                yield db, records, previous, initial
        except (sqlite3.Error, json.JSONDecodeError, UnicodeError, AttributeError, KeyError, TypeError, RecursionError) as error:
            raise ArchiveUnavailable("archive state unavailable") from error

    def _append(self, db, records, previous, **details):
        body = {"version": 2, "store_id": self.store_id, "sequence": len(records) + 1,
                "predecessor": previous, **details}
        sequence = body["sequence"]
        tag = self.mac(self.receipt_key, b"archive-record-v1", body)
        db.execute("INSERT INTO records VALUES(?,?,?)", (sequence, canonical(body), tag))
        db.execute("UPDATE head SET seq=?,tag=?,proof=? WHERE singleton=1",
                   (sequence, tag, self.head_proof(sequence, tag)))
        return {**body, "tag": tag}

    def position(self, token):
        with self.verified(write=False) as (db, records, head, initial):
            grant = self.authorize(db, token, "producer")
            outstanding = records[-1] if records and records[-1]["state"] == "PENDING" else None
            return {"store_id": self.store_id, "sequence": len(records), "tag": head,
                    "proof": self.head_proof(len(records), head),
                    "terminal_position": outstanding["predecessor"] if outstanding else head,
                    "initial_projection": initial,
                    "capacity": {"used": len(records), "remaining": MAX_RECORDS - len(records),
                                 "can_accept_intent": outstanding is None and len(records) + 2 <= MAX_RECORDS},
                    "has_pending": outstanding is not None,
                    "pending": (outstanding if outstanding and
                                producer_allows(grant, outstanding) else None)}

    def append_intent(self, token, operation_id, raw_event, *, predecessor, deadline_ms, expected):
        identifier(operation_id)
        digest(predecessor)
        integer(deadline_ms)
        event = decode_event(raw_event)
        projection_schema(expected)
        kind = event["kind"]
        creating = event["authorization"] == "allow" and kind in CREATION_KINDS
        with self.verified(write=True) as (db, records, head, initial):
            grant = self.authorize(db, token, "producer")
            producer = grant["principal"]
            if (event["kind"] not in grant["scopes"] or event["node"] != grant["node"]
                    or event["subsystem"] != grant["subsystem"]):
                raise ArchiveDenied("event outside producer scope")
            intent_projection(event, expected)
            for record in records:
                if record["state"] != "PENDING" or record["producer"] != producer:
                    continue
                if record["operation_id"] == operation_id:
                    if (record["event"] == event and record["predecessor"] == predecessor
                            and record["deadline_ms"] == deadline_ms and record["expected"] == expected):
                        return record
                    raise ArchiveConflict("operation ID already bound")
                if record["event"]["event_id"] == event["event_id"]:
                    raise ArchiveConflict("event ID already bound")
            if records and records[-1]["state"] == "PENDING":
                raise ArchiveConflict("unresolved pending operation")
            if predecessor != head or deadline_ms <= self.now():
                raise ArchiveConflict("invalid predecessor or expired intent")
            latest = {(entry["kind"], entry["id"]): entry for entry in initial["entities"]}
            for record in records:
                if record["state"] == "CONFIRMED":
                    for old, new in zip(record["outcome"]["before"]["entities"],
                                        record["outcome"]["after"]["entities"]):
                        if old != new:
                            latest[new["kind"], new["id"]] = new
            if kind == "access_decision" and event["reason"] == "unknown_resource":
                asset = latest.get(("asset", event["entity_id"]))
                if asset is not None and asset["version"] != 0:
                    raise ArchiveConflict("known asset cannot be recorded as unknown")
            for entry in expected["entities"]:
                known = latest.get((entry["kind"], entry["id"]))
                new_entity = creating and (entry["kind"], entry["id"]) == (CREATION_KINDS[kind], event["entity_id"])
                denied_absence = event["authorization"] == "deny" and entry["version"] == 0
                if known is None and not (new_entity or denied_absence):
                    raise ArchiveConflict("intent references unanchored state")
                if known is not None and (known != entry or new_entity):
                    raise ArchiveConflict("intent disagrees with latest retained projection")
            if kind == "detector_alert":
                self.check_detector_sources(records, event)
            if len(records) + 2 > MAX_RECORDS:
                raise ArchiveUnavailable("archive capacity exhausted")
            return self._append(db, records, head, producer=producer, operation_id=operation_id,
                               state="PENDING", event=event, deadline_ms=deadline_ms, expected=expected,
                                node=grant["node"], subsystem=grant["subsystem"])

    @staticmethod
    def check_detector_sources(records, event):
        confirmed = {record["pending_tag"] for record in records if record["state"] == "CONFIRMED"}
        retained = {(record["producer"], record["event"]["event_id"]) for record in records
                    if record["tag"] in confirmed and record["event"]["kind"] == "detector_source"}
        if any((source["producer"], source["event_id"]) not in retained for source in event["source_ids"]):
            raise ArchiveConflict("alert references unavailable retained source evidence")

    def record_telemetry(self, token, raw_event):
        """Commit a source or derived observation entirely within the evidence store."""
        event = decode_event(raw_event)
        kind, operation = event["kind"], event["event_id"]
        if (kind not in TELEMETRY_KINDS or event["authorization"] != "observed"
                or "detector_context" not in event or self.store_id != "detector-evidence"):
            raise ValueError("expected a canonical detector observation in the detector archive")
        expected = {"schema": 1, "entities": []}
        with self.verified(write=True) as (db, records, head, _initial):
            grant = self.authorize(db, token, "producer")
            producer = grant["principal"]
            if (kind not in grant["scopes"] or event["node"] != grant["node"]
                    or event["subsystem"] != grant["subsystem"]):
                raise ArchiveDenied("event outside producer scope")
            for record in records:
                if record["state"] == "PENDING" and record["producer"] == producer and record["operation_id"] == operation:
                    terminal = next((r for r in records if r.get("pending_tag") == record["tag"]), None)
                    if record["event"] == event and terminal and terminal["state"] == "CONFIRMED":
                        return terminal
                    raise ArchiveConflict("detector observation conflicts with retained evidence")
            if records and records[-1]["state"] == "PENDING":
                raise ArchiveConflict("unresolved pending operation")
            if kind == "detector_alert":
                self.check_detector_sources(records, event)
            if len(records) + 2 > MAX_RECORDS:
                raise ArchiveUnavailable("archive capacity exhausted")
            pending = self._append(db, records, head, producer=producer, operation_id=operation,
                                   state="PENDING", event=event, deadline_ms=self.now() + 5000,
                                   expected=expected, node=grant["node"], subsystem=grant["subsystem"])
            outcome = {"basis": "verified_commit", "before": expected, "after": expected, "delivery": "unknown"}
            return self._terminal(db, [*records, pending], pending["tag"], pending, outcome)

    def finalize(self, token, pending_tag, outcome):
        digest(pending_tag)
        with self.verified(write=True) as (db, records, head, _initial):
            grant = self.authorize(db, token, "producer")
            pending = self.pending_record(records, pending_tag)
            if not producer_allows(grant, pending):
                raise ArchiveDenied("pending receipt outside producer scope")
            return self._terminal(db, records, head, pending, outcome)

    @staticmethod
    def pending_record(records, pending_tag):
        pending = next((r for r in records if r["tag"] == pending_tag and r["state"] == "PENDING"), None)
        if pending is None:
            raise ArchiveConflict("unknown pending receipt")
        return pending

    def _terminal(self, db, records, head, pending, outcome, **recovery):
        outcome_schema(outcome, pending)
        pending_tag = pending["tag"]
        state = "CONFIRMED" if outcome["basis"] == "verified_commit" else "ABORTED"
        for record in records:
            if record.get("pending_tag") == pending_tag:
                if record["state"] == state and record["outcome"] == outcome:
                    return record
                raise ArchiveConflict("terminal outcome already recorded")
        if head != pending_tag:
            raise ArchiveConflict("pending receipt is not at the archive head")
        return self._append(db, records, head, producer=pending["producer"],
                           operation_id=pending["operation_id"], state=state,
                           pending_tag=pending_tag, outcome=outcome, node=pending["node"],
                           subsystem=pending["subsystem"], **recovery)

    def grant_recovery(self, token, principal, pending_tag, outcome, expires_ms):
        """Trusted offline authority binds a separate credential to one verified outcome."""
        identifier(principal)
        digest(pending_tag)
        integer(expires_ms)
        if expires_ms <= self.now():
            raise ArchiveDenied("recovery grant already expired")
        hashed = self.token_digest(token)
        grant = {"principal": principal, "pending_tag": pending_tag, "expires_ms": expires_ms,
                 "outcome_digest": hashlib.sha256(canonical(outcome)).hexdigest()}
        with self.verified(write=True) as (db, records, head, _):
            if head != pending_tag:
                raise ArchiveConflict("only the outstanding intent may be authorized")
            pending = self.pending_record(records, pending_tag)
            if principal == pending["producer"] or db.execute(
                "SELECT 1 FROM grants WHERE digest=?", (hashed,)
            ).fetchone():
                raise ArchiveDenied("recovery requires a distinct identity and credential")
            outcome_schema(outcome, pending)
            proof = self.mac(self.grant_key, b"archive-recovery-grant-v1", [hashed, grant])
            db.execute("INSERT INTO recovery_grants VALUES(?,?,?)", (hashed, canonical(grant), proof))

    def recover(self, token, pending_tag, outcome):
        digest(pending_tag)
        hashed = self.token_digest(token)
        with self.verified(write=True) as (db, records, head, _):
            row = db.execute("SELECT body,proof FROM recovery_grants WHERE digest=?", (hashed,)).fetchone()
            if row is None:
                raise ArchiveDenied("unknown recovery credential")
            grant = json.loads(row[0])
            proof = self.mac(self.grant_key, b"archive-recovery-grant-v1", [hashed, grant])
            if row[0] != canonical(grant) or not hmac.compare_digest(row[1], proof):
                raise ArchiveUnavailable("invalid recovery grant")
            if (grant["pending_tag"] != pending_tag or grant["expires_ms"] <= self.now()
                    or grant["outcome_digest"] != hashlib.sha256(canonical(outcome)).hexdigest()):
                raise ArchiveDenied("recovery credential outside verified outcome")
            pending = self.pending_record(records, pending_tag)
            return self._terminal(db, records, head, pending, outcome, recovery_actor=grant["principal"])

    def retrieve(self, token, producer, event_id):
        identifier(producer)
        identifier(event_id)
        with self.verified(write=False) as (db, records, _, _initial):
            grant = self.authorize(db, token, "investigator")
            for record in records:
                event = record.get("event")
                if record["producer"] == producer and event and event["event_id"] == event_id:
                    if event["kind"] not in grant["scopes"]:
                        raise ArchiveDenied("event outside investigator scope")
                    terminal = next((r for r in records if r.get("pending_tag") == record["tag"]), None)
                    lifecycle = terminal["state"] if terminal else "PENDING"
                    return {"event_bytes": canonical(event), "intent_receipt": record,
                            "terminal_receipt": terminal, "lifecycle": lifecycle,
                            "mutation_committed": (lifecycle == "CONFIRMED"
                                                   and event["kind"] in STATE_MUTATIONS
                                                   and event["authorization"] == "allow"
                                                   and terminal["outcome"]["before"] != terminal["outcome"]["after"])}
            raise LookupError("unknown retained event")
