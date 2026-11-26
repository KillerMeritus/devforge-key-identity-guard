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
KINDS = frozenset({
    "access_decision", "evidence_access", "enrolment", "revocation", "role_change",
    "grant_change", "approval_issue", "approval_consume", "rotation", "backup_verify",
    "restore", "trust_change", "archive_control", "detector_source", "detector_alert",
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
    "approval_consume", "rotation", "restore", "trust_change",
})
KINDS_WITH_EVIDENCE = {"detector_alert"}


def event_schema(value):
    fields(value, "version event_id request_id principal node kind entity_id result reason received_ms source_ids")
    if type(value["version"]) is not int or value["version"] != 1 or value["kind"] not in KINDS:
        raise ValueError("unsupported event schema or kind")
    for name in ("event_id", "request_id", "principal", "node", "entity_id", "reason"):
        identifier(value[name])
    if value["result"] not in ("allow", "deny", "observed", "unavailable"):
        raise ValueError("invalid event result")
    integer(value["received_ms"])
    sources = value["source_ids"]
    if not isinstance(sources, list) or len(sources) > 32:
        raise ValueError("invalid evidence references")
    for source in sources:
        identifier(source)
    if len(set(sources)) != len(sources) or (value["kind"] in KINDS_WITH_EVIDENCE and not sources):
        raise ValueError("missing or duplicate evidence references")


def outcome_schema(outcome, event):
    fields(outcome, "basis entity_id before_version after_version before_digest after_digest")
    if (outcome["basis"] not in ("verified_commit", "verified_noncommit")
            or outcome["entity_id"] != event["entity_id"]):
        raise ValueError("outcome must bind an explicit state and entity")
    for name in ("before_version", "after_version"):
        integer(outcome[name])
    for name in ("before_digest", "after_digest"):
        digest(outcome[name])
    same_state = (outcome["before_version"], outcome["before_digest"]) == (
        outcome["after_version"], outcome["after_digest"])
    if outcome["basis"] == "verified_noncommit" and not same_state:
        raise ValueError("abort cannot change state")
    if (outcome["basis"] == "verified_commit" and event["kind"] in STATE_MUTATIONS
            and event["result"] == "allow" and same_state):
        raise ValueError("successful mutation must bind a state change")


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

    def provision(self, grants):
        """Create a new archive exclusively. Never run from a request path."""
        prepared = []
        for token, grant in grants.items():
            token_digest = self.token_digest(token)
            fields(grant, "principal role scopes expires_ms revoked")
            identifier(grant["principal"])
            if grant["role"] not in ("producer", "investigator") or type(grant["revoked"]) is not bool:
                raise ValueError("invalid role or status")
            integer(grant["expires_ms"])
            scopes = grant["scopes"]
            if not isinstance(scopes, list) or not scopes or len(scopes) > 32:
                raise ValueError("explicit scopes required")
            for scope in scopes:
                identifier(scope)
            data = canonical(grant)
            prepared.append((token_digest, data, self.mac(
                self.grant_key, b"archive-grant-v1", [token_digest, grant])))
        fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        with transaction(self.path) as db:
            db.execute("CREATE TABLE head(singleton INTEGER PRIMARY KEY CHECK(singleton=1), seq INTEGER, tag TEXT, proof TEXT)")
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
                yield db, records, previous
        except (sqlite3.Error, json.JSONDecodeError, UnicodeError, AttributeError, KeyError, TypeError, RecursionError) as error:
            raise ArchiveUnavailable("archive state unavailable") from error

    def _append(self, db, records, previous, **details):
        body = {"version": 1, "store_id": self.store_id, "sequence": len(records) + 1,
                "predecessor": previous, **details}
        sequence = body["sequence"]
        tag = self.mac(self.receipt_key, b"archive-record-v1", body)
        db.execute("INSERT INTO records VALUES(?,?,?)", (sequence, canonical(body), tag))
        db.execute("UPDATE head SET seq=?,tag=?,proof=? WHERE singleton=1",
                   (sequence, tag, self.head_proof(sequence, tag)))
        return {**body, "tag": tag}

    def position(self, token):
        with self.verified(write=False) as (db, records, head):
            grant = self.authorize(db, token, "producer")
            outstanding = records[-1] if records and records[-1]["state"] == "PENDING" else None
            return {"store_id": self.store_id, "sequence": len(records), "tag": head,
                    "proof": self.head_proof(len(records), head),
                    "terminal_position": outstanding["predecessor"] if outstanding else head,
                    "has_pending": outstanding is not None,
                    "pending": (outstanding if outstanding and
                                outstanding["producer"] == grant["principal"] and
                                outstanding["event"]["kind"] in grant["scopes"] else None)}

    def append_intent(self, token, operation_id, raw_event, *, predecessor, deadline_ms, expected):
        identifier(operation_id)
        digest(predecessor)
        integer(deadline_ms)
        event = decode_event(raw_event)
        fields(expected, "version digest")
        integer(expected["version"])
        digest(expected["digest"])
        with self.verified(write=True) as (db, records, head):
            grant = self.authorize(db, token, "producer")
            producer = grant["principal"]
            if event["kind"] not in grant["scopes"]:
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
            if len(records) + 2 > MAX_RECORDS:
                raise ArchiveUnavailable("archive capacity exhausted")
            return self._append(db, records, head, producer=producer, operation_id=operation_id,
                               state="PENDING", event=event, deadline_ms=deadline_ms, expected=expected)

    def finalize(self, token, pending_tag, outcome):
        digest(pending_tag)
        with self.verified(write=True) as (db, records, head):
            grant = self.authorize(db, token, "producer")
            pending = next((r for r in records if r["tag"] == pending_tag and r["state"] == "PENDING"), None)
            if pending is None:
                raise ArchiveConflict("unknown pending receipt")
            if pending["producer"] != grant["principal"] or pending["event"]["kind"] not in grant["scopes"]:
                raise ArchiveDenied("pending receipt outside producer scope")
            outcome_schema(outcome, pending["event"])
            expected = pending["expected"]
            if (outcome["before_version"], outcome["before_digest"]) != (expected["version"], expected["digest"]):
                raise ArchiveConflict("outcome pre-state disagrees with intent")
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
                               pending_tag=pending_tag, outcome=outcome)

    def retrieve(self, token, producer, event_id):
        identifier(producer)
        identifier(event_id)
        with self.verified(write=False) as (db, records, _):
            grant = self.authorize(db, token, "investigator")
            for record in records:
                event = record.get("event")
                if record["producer"] == producer and event and event["event_id"] == event_id:
                    if event["kind"] not in grant["scopes"]:
                        raise ArchiveDenied("event outside investigator scope")
                    terminal = next((r for r in records if r.get("pending_tag") == record["tag"]), None)
                    return {"event_bytes": canonical(event), "intent_receipt": record,
                            "terminal_receipt": terminal}
            raise LookupError("unknown retained event")
