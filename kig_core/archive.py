"""Isolated local archive. Workers must verify committed rows before finalizing."""
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
           + (" rule_id rule_version approval_ref" if kind == "detector_alert" else ""))
    if type(value["version"]) is not int or value["version"] != 2 or kind not in KINDS:
        raise ValueError("unsupported event schema or kind")
    for name in ("event_id", "request_id", "actor", "node", "subsystem", "entity_id", "reason"):
        identifier(value[name])
    if value["authorization"] not in ("allow", "deny", "observed", "unavailable"):
        raise ValueError("invalid event result")
    if rotation:
        identifier(value["approval_id"])
        if value["reason"] != "approved":
            raise ValueError("authorized rotation requires a valid approval decision")
    if kind in CREATION_KINDS and value["authorization"] == "allow" and value["reason"] != "authorized":
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
    if outcome["basis"] == "verified_noncommit":
        if before != after or outcome["delivery"] != "withheld":
            raise ValueError("abort must leave state unchanged and withhold response data")
    elif event["authorization"] == "allow" and event["kind"] in STATE_MUTATIONS:
        kind = event["kind"]
        changes = list(zip(before["entities"], after["entities"]))
        if kind == "revocation":
            old, new = changes[0]
            if event["reason"] == "already_revoked":
                if old["status"] != "revoked" or before != after:
                    raise ValueError("idempotent revocation requires unchanged revoked state")
            elif (old["status"] != "active" or new["status"] != "revoked"
                  or new["version"] != old["version"] + 1 or old["digest"] == new["digest"]):
                raise ValueError("revocation must transition active state to revoked")
        elif kind in CREATION_KINDS:
            if any(old["version"] != 0 or new["version"] != 1 for old, new in changes):
                raise ValueError("creation must transition from absent to version one")
            if kind == "enrolment" and after["entities"][0]["status"] != "active":
                raise ValueError("enrolment must establish an active credential")
        elif kind == "rotation":
            for old, new in changes:
                if old["version"] == 0 or old["digest"] == new["digest"]:
                    raise ValueError("rotation requires existing state and new content")
                if old["kind"] == "asset" and new["version"] != old["version"] + 1:
                    raise ValueError("rotation must advance the asset by one version")
                if old["kind"] == "approval" and new["version"] != 0:
                    raise ValueError("rotation must consume its bound approval")
        elif before == after:
            raise ValueError("successful mutation must bind a state change")
    elif before != after:
        raise ValueError("non-mutation or denied intent cannot change projected state")


def producer_allows(grant, record):
    return (record["producer"] == grant["principal"] and record["node"] == grant["node"]
            and record["subsystem"] == grant["subsystem"] and record["event"]["kind"] in grant["scopes"])



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
        keys = projection_schema(expected)
        kind = event["kind"]
        creating = event["authorization"] == "allow" and kind in CREATION_KINDS
        no_projection = kind in TELEMETRY_KINDS or (
            kind == "access_decision" and event["authorization"] == "deny"
            and event["reason"] == "unknown_resource")
        if no_projection:
            if keys:
                raise ValueError("this event must not assert entity state")
        elif event["entity_id"] not in {entity_id for _, entity_id in keys}:
            raise ValueError("intent must cover the event entity")
        if creating and (keys != [(CREATION_KINDS[kind], event["entity_id"])]
                         or expected["entities"][0]["version"] != 0):
            raise ValueError("creation must bind one absent entity")
        if kind == "revocation" and event["authorization"] == "allow" and (
            keys != [("credential", event["entity_id"])]
            or event["reason"] not in ("revoked", "already_revoked")
        ):
            raise ValueError("revocation must bind a credential and a supported decision")
        if kind == "rotation" and event["authorization"] == "allow":
            if keys != [("approval", event["approval_id"]), ("asset", event["entity_id"])] or any(
                item["version"] == 0 for item in expected["entities"]
            ):
                raise ValueError("rotation must cover the asset and its live approval")
        with self.verified(write=True) as (db, records, head, initial):
            grant = self.authorize(db, token, "producer")
            producer = grant["principal"]
            if (event["kind"] not in grant["scopes"] or event["node"] != grant["node"]
                    or event["subsystem"] != grant["subsystem"]):
                raise ArchiveDenied("event outside producer scope")
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
                    for entry in record["outcome"]["after"]["entities"]:
                        latest[entry["kind"], entry["id"]] = entry
            if kind == "access_decision" and no_projection:
                asset = latest.get(("asset", event["entity_id"]))
                if asset is not None and asset["version"] != 0:
                    raise ArchiveConflict("known asset cannot be recorded as unknown")
            for entry in expected["entities"]:
                known = latest.get((entry["kind"], entry["id"]))
                if known is None and not creating:
                    raise ArchiveConflict("intent references unanchored state")
                if known is not None and (known != entry or creating):
                    raise ArchiveConflict("intent disagrees with latest retained projection")
            if kind == "detector_alert":
                confirmed = {record["pending_tag"] for record in records if record["state"] == "CONFIRMED"}
                retained = {(record["producer"], record["event"]["event_id"]) for record in records
                            if record["tag"] in confirmed and record["event"]["kind"] == "detector_source"}
                if any((source["producer"], source["event_id"]) not in retained
                       for source in event["source_ids"]):
                    raise ArchiveConflict("alert references unavailable retained source evidence")
            if len(records) + 2 > MAX_RECORDS:
                raise ArchiveUnavailable("archive capacity exhausted")
            return self._append(db, records, head, producer=producer, operation_id=operation_id,
                               state="PENDING", event=event, deadline_ms=deadline_ms, expected=expected,
                                node=grant["node"], subsystem=grant["subsystem"])

    def finalize(self, token, pending_tag, outcome):
        digest(pending_tag)
        with self.verified(write=True) as (db, records, head, _initial):
            grant = self.authorize(db, token, "producer")
            pending = next((r for r in records if r["tag"] == pending_tag and r["state"] == "PENDING"), None)
            if pending is None:
                raise ArchiveConflict("unknown pending receipt")
            if not producer_allows(grant, pending):
                raise ArchiveDenied("pending receipt outside producer scope")
            outcome_schema(outcome, pending)
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
                               pending_tag=pending_tag, outcome=outcome,
                                node=grant["node"], subsystem=grant["subsystem"])

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
