"""Opt-in archive enforcement for the two local HTTP workers."""
from contextlib import closing, contextmanager
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import tempfile
import time

from .archive import Archive, ArchiveConflict, ArchiveUnavailable, GENESIS, canonical, identifier, outcome_schema
from .db import deadline, transaction
from .guard import ARCHIVE_MODE, ARCHIVE_MODE_FILE


WORKER_KINDS = ("access_decision", "enrolment", "revocation", "rotation", "evidence_access")
WORKER_ACTIONS = {"read": "access_decision", "revoke": "revocation", "rotate": "rotation",
                  "enroll": "enrolment", "evidence": "evidence_access"}
MUTATIONS = {"revoke", "rotate", "enroll"}
ANCHOR = ("audit_anchor", "cutoff")
MARKER_TABLE = "archive_markers"
LOCK_TIMEOUT = 5


class RetryDenied(PermissionError):
    pass


class PendingRecovery(ArchiveUnavailable):
    """Verified archive head is pending an operator recovery decision."""


class ControlledRollback(RuntimeError):
    """Signal a deliberate live rollback before the working commit."""


def digest(value):
    return hashlib.sha256(value).hexdigest()


def reference(value):
    try:
        identifier(value)
    except ValueError:
        return "sha256-" + digest(value.encode())
    return value


def entity(kind, name, version, value, **details):
    return {"kind": kind, "id": name, "version": version,
            "digest": digest(canonical(value)) if version else GENESIS, **details}


def absent(kind, name):
    details = {"status": "absent"} if kind == "credential" else {}
    return entity(kind, name, 0, None, **details)


def manifest(entities):
    return {"schema": 1, "entities": [entities[key] for key in sorted(entities)]}


def select(entities, keys):
    return manifest({key: entities.get(key, absent(*key)) for key in keys})


def row_entities(db, guard):
    rows = {}

    def add(kind, name, version, value, **details):
        identifier(name)
        rows[kind, name] = entity(kind, name, version, value, **details)

    for device, actor, role, revoked in db.execute("SELECT token,actor,role,revoked FROM devices"):
        if revoked not in (0, 1) or role not in ("reader", "admin") or not isinstance(actor, str):
            raise ArchiveUnavailable("invalid persisted credential")
        add("credential", device, 1 + revoked,
            [device, actor, role, revoked, 1], status="revoked" if revoked else "active")
    key_id = hmac.digest(guard.storage_key, b"devforge-archive-file-root-v1", "sha256").hex()
    grants = {}
    for actor, file in db.execute("SELECT actor,file FROM grants ORDER BY actor,file"):
        grants.setdefault(file, []).append(actor)
    for name, encrypted, version in db.execute("SELECT id,body,version FROM files"):
        if type(version) is not int or version <= 0 or type(encrypted) is not bytes:
            raise ArchiveUnavailable("invalid persisted asset")
        add("asset", name, version, [name, key_id, version, digest(encrypted)])
        add("grant", name, 1, [name, grants.pop(name, [])])
    if grants:
        raise ArchiveUnavailable("orphaned persisted grants")
    for approval, actor, target, version, expires in db.execute(
        "SELECT id,actor,target,version,expires FROM approvals"
    ):
        approval_ref = digest(approval.encode())
        add("approval", approval_ref, 1,
            [approval_ref, actor, target, "rotate", version, float(expires).hex(), "issued"])
    return rows


def audit_head(db):
    return db.execute("SELECT seq,tag FROM audit_head WHERE singleton=1").fetchone() or (0, "")


def anchor(position):
    return entity(*ANCHOR, 1, list(position))


def archive_directory(state):
    return Path(state) / "archive"


def open_archive(state):
    directory = archive_directory(state)
    return Archive(directory / "audit.sqlite", "track4",
                   receipt_key=(directory / "receipt.key").read_bytes(),
                   grant_key=(directory / "grant.key").read_bytes())


def private_write(path, data):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def provision_archive(state, guard, *, producer_expires_ms=None):
    """Provision a known-good stopped fixture. Return independently scoped credentials."""
    directory = archive_directory(state)
    working = Path(guard.path).resolve()
    if working != (Path(state) / "demo.sqlite").resolve():
        raise ValueError("archive must bind its own working database")
    guard.require_mode(archive=False)
    directory.mkdir(mode=0o700)
    private_write(directory.parent / ARCHIVE_MODE_FILE, ARCHIVE_MODE)
    fd = os.open(directory.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    for filename in ("receipt.key", "grant.key"):
        private_write(directory / filename, secrets.token_bytes(32))
    private_write(directory / "store.lock", b"")
    archive = open_archive(state)
    credentials = {name: secrets.token_urlsafe(32) for name in
                   ("producer-A", "producer-B", "investigator")}
    expires = archive.now() + 3_600_000
    common = {"scopes": list(WORKER_KINDS), "revoked": False}
    grants = {credentials["investigator"]: {**common, "principal": "investigator",
                                           "role": "investigator", "expires_ms": expires}}
    for node in ("A", "B"):
        name = f"producer-{node}"
        private_write(directory / name, credentials[name].encode())
        grants[credentials[name]] = {**common, "principal": f"worker-{node}", "role": "producer",
                                     "node": node, "subsystem": "worker",
                                     "expires_ms": producer_expires_ms if producer_expires_ms is not None else expires}
    with store_lock(directory), guard.transaction(archive=True) as db:
        guard.audit(db)
        db.execute(f"CREATE TABLE {MARKER_TABLE}(pending_tag TEXT PRIMARY KEY, body BLOB, proof TEXT)")
        db.execute("CREATE TABLE archive_cutoff(singleton INTEGER PRIMARY KEY CHECK(singleton=1), seq INTEGER, tag TEXT)")
        cutoff = audit_head(db)
        db.execute("INSERT INTO archive_cutoff VALUES(1,?,?)", cutoff)
        rows = row_entities(db, guard)
        rows[ANCHOR] = anchor(cutoff)
        archive.provision(grants, initial=manifest(rows))
    return credentials


@contextmanager
def store_lock(directory):
    end = time.monotonic() + LOCK_TIMEOUT
    fd = os.open(directory / "store.lock", os.O_RDONLY | os.O_NOFOLLOW)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ArchiveUnavailable("invalid archive lock")
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                remaining = end - time.monotonic()
                if remaining <= 0:
                    raise ArchiveUnavailable("archive lock unavailable") from None
                time.sleep(min(0.01, remaining))
        token = deadline.set(end)
        try:
            yield
        finally:
            deadline.reset(token)
    finally:
        os.close(fd)


def archive_state(records, initial):
    latest = {(item["kind"], item["id"]): item for item in initial["entities"]}
    pending, confirmed = None, []
    for record in records:
        if record["state"] == "PENDING":
            if pending is not None:
                raise ArchiveUnavailable("archive contains concurrent pending intents")
            pending = record
            continue
        if (pending is None or record.get("pending_tag") != pending["tag"]
                or record["state"] not in ("CONFIRMED", "ABORTED")):
            raise ArchiveUnavailable("archive terminal order mismatch")
        if record["state"] == "CONFIRMED":
            confirmed.append((pending, record))
            for old, new in zip(record["outcome"]["before"]["entities"],
                                record["outcome"]["after"]["entities"]):
                if old != new:
                    latest[new["kind"], new["id"]] = new
        pending = None
    return latest, confirmed


class ArchivedGuard:
    def __init__(self, guard, state, node=None):
        if Path(guard.path).resolve() != (Path(state) / "demo.sqlite").resolve():
            raise ValueError("archive must bind its own working database")
        guard.require_mode(archive=True)
        self.guard = guard
        self.directory = archive_directory(state)
        self.archive = open_archive(state)
        self.node = node
        self.producer = (self.directory / f"producer-{node}").read_text() if node is not None else None

    def marker_proof(self, raw):
        return hmac.digest(self.guard.audit_key, b"archive-worker-marker-v1\0" + raw, "sha256").hex()

    def verify(self, db, records, initial, *, recover_pending=False):
        latest, confirmed = archive_state(records, initial)
        pending = records[-1] if records and records[-1]["state"] == "PENDING" else None
        if pending and not recover_pending:
            raise PendingRecovery("unresolved pending operation")
        cutoff = db.execute("SELECT seq,tag FROM archive_cutoff WHERE singleton=1").fetchone()
        if cutoff is None or anchor(cutoff) != latest.pop(ANCHOR, None):
            raise ArchiveUnavailable("working archive cutoff mismatch")
        if cutoff[0] and db.execute("SELECT tag FROM audit WHERE id=?", (cutoff[0],)).fetchone() != (cutoff[1],):
            raise ArchiveUnavailable("working archive cutoff missing")
        events = self.guard.audit(db)
        markers = {}
        for pending_tag, raw, proof in db.execute(f"SELECT pending_tag,body,proof FROM {MARKER_TABLE}"):
            if not hmac.compare_digest(proof, self.marker_proof(raw)):
                raise ArchiveUnavailable("invalid working transaction marker")
            marker = json.loads(raw)
            if raw != canonical(marker) or marker["pending_tag"] != pending_tag:
                raise ArchiveUnavailable("working transaction marker mismatch")
            markers[pending_tag] = marker

        def verify_marker(intent, marker, previous, expected_outcome=None):
            if marker is None:
                raise ArchiveUnavailable("missing working transaction marker")
            sequence, tag = marker["position"]
            event = intent["event"]
            binding = (marker["operation_id"], marker["request_id"], marker["node"])
            if (binding != (intent["operation_id"], event["request_id"], intent["node"])
                    or expected_outcome is not None and marker["outcome"] != expected_outcome
                    or marker["outcome"]["basis"] != "verified_commit"
                    or marker["outcome"]["before"] != intent["expected"]
                    or sequence != previous[0] + 1 or sequence > len(events)
                    or events[sequence - 1].get("request_id") != event["request_id"]
                    or db.execute("SELECT tag FROM audit WHERE id=?", (sequence,)).fetchone() != (tag,)):
                raise ArchiveUnavailable("working transaction marker binding mismatch")
            return sequence, tag

        position = cutoff
        for intent, terminal in confirmed:
            marker = markers.pop(intent["tag"], None)
            position = verify_marker(intent, marker, position, terminal["outcome"])
        candidate = markers.pop(pending["tag"], None) if pending else None
        if candidate is not None:
            position = verify_marker(pending, candidate, position)
            for item in candidate["outcome"]["after"]["entities"]:
                latest[item["kind"], item["id"]] = item
        if markers or audit_head(db) != position:
            raise ArchiveUnavailable("working history and archive disagree")
        actual = row_entities(db, self.guard)
        expected = {key: item for key, item in latest.items() if item["version"]}
        if actual != expected:
            raise ArchiveUnavailable("persisted state differs from retained projection")
        return actual, events, candidate

    def prepare_rotation(self, token, target, version):
        if type(version) is not int:
            return None
        guard = self.guard
        with store_lock(self.directory), guard.transaction(write=False, archive=True) as db:
            with self.archive.verified(write=False) as (archive_db, records, _, initial):
                self.archive.authorize(archive_db, self.producer, "producer")
                self.verify(db, records, initial)
            identity = guard.identity(db, token)
            row = None
            if identity and identity[1:] == ("admin", 0):
                row = db.execute("SELECT body FROM files WHERE id=? AND version=?", (target, version)).fetchone()
        if row is None:
            return None
        prepared = guard.encrypt(target, version + 1, guard.decrypt(target, version, row[0]))
        guard.checkpoint("prepared")
        return prepared

    def request_binding(self, token, action, target, version, approval, key):
        if not key:
            return secrets.token_hex(16), None
        identifier(key)
        credential = self.guard.digest(token)
        request_id = digest(canonical([credential, action, key]))
        return request_id, hmac.digest(self.guard.audit_key, b"archive-worker-request-v1\0" +
                                      canonical([credential, action, target, version, approval]), "sha256").hex()

    def retry(self, records, db, request_id, binding, identity, action):
        intents = {r["tag"]: r for r in records if r["state"] == "PENDING"
                   and r["operation_id"] == request_id}
        if not intents:
            return None
        if not identity or identity[1] != "admin" or identity[2]:
            raise RetryDenied("retry is no longer authorized")
        if len(intents) != 1:
            raise ArchiveConflict("duplicate working operation")
        tag, pending = next(iter(intents.items()))
        terminal = next((item for item in records if item.get("pending_tag") == tag), None)
        if terminal is None or terminal["state"] != "CONFIRMED":
            raise ArchiveConflict("operation cannot be replayed")
        row = db.execute(f"SELECT body FROM {MARKER_TABLE} WHERE pending_tag=?", (tag,)).fetchone()
        marker = json.loads(row[0])
        if marker["binding"] != binding or pending["event"]["kind"] != WORKER_ACTIONS[action]:
            raise ArchiveConflict("idempotency key is already bound")
        result = {**marker["result"], "request_id": request_id}
        if action == "enroll" and result["allowed"]:
            result["device_ref"] = pending["event"]["entity_id"]
        return result

    @contextmanager
    def working_transaction(self):
        context = {}
        rolled_back = False

        def observe_rollback():
            nonlocal rolled_back
            rolled_back = True

        try:
            with self.guard.transaction(archive=True, on_rollback=observe_rollback) as db:
                yield db, context
        except Exception as error:
            pending = context.get("pending")
            if not rolled_back or pending is None:
                raise
            try:
                self.abort_rolled_back(pending)
            except Exception as reconciliation_error:
                error.add_note("Could not verify and record the rollback")
                raise error from reconciliation_error
            if isinstance(error, ControlledRollback):
                raise ArchiveUnavailable("operation rolled back") from error
            raise

    def abort_rolled_back(self, pending):
        with self.guard.transaction(write=False, archive=True) as db:
            with self.archive.verified(write=False) as (_, records, head, initial):
                _, _, marker = self.verify(db, records, initial, recover_pending=True)
                if marker is not None or head != pending["tag"]:
                    raise ArchiveUnavailable("controlled rollback cannot be verified")
            before = pending["expected"]
            self.archive.finalize(self.producer, pending["tag"], {
                "basis": "verified_noncommit", "before": before, "after": before,
                "delivery": "withheld",
            })
            with self.archive.verified(write=False) as (_, records, _, initial):
                self.verify(db, records, initial)

    def execute(self, token, action, target, *, version=None, approval=None, public_key=None,
                challenge=None, idempotency_key=None, render=None):
        if action in MUTATIONS and not idempotency_key:
            raise ValueError("archived mutations require an idempotency key")
        guard = self.guard
        request_id, binding = self.request_binding(
            token, action, target, version, approval, idempotency_key if action in MUTATIONS else None,
        )
        prepared = self.prepare_rotation(token, target, version) if action == "rotate" else None
        with store_lock(self.directory):
            with self.working_transaction() as (db, context):
                with self.archive.verified(write=False) as (archive_db, records, head, initial):
                    self.archive.authorize(archive_db, self.producer, "producer")
                    before, events, _ = self.verify(db, records, initial)
                identity = guard.identity(db, token)
                if binding:
                    replay = self.retry(records, db, request_id, binding, identity, action)
                    if replay is not None:
                        return replay
                actor, role, revoked = identity or (None, None, False)
                evidence = None
                if revoked:
                    result = {"allowed": False, "reason": "revoked_device"}
                elif not identity:
                    result = {"allowed": False, "reason": "invalid_device"}
                elif action == "evidence":
                    evidence = next((event for event in events if event.get("request_id") == target), None)
                    allowed = role == "admin" and evidence is not None
                    reason = "evidence_verified" if allowed else (
                        "unknown_request" if role == "admin" else "action_forbidden")
                    result = {"allowed": allowed, "reason": reason}
                else:
                    result = guard.apply(db, actor, role, action, target, version, approval,
                                         public_key, challenge, prepared)
                result["request_id"] = request_id
                after = row_entities(db, guard)
                event, keys = self.prepare_event(
                    action, target, approval, token, actor, result, before, after,
                )
                expected, resulting = select(before, keys), select(after, keys)
                outcome = {"basis": "verified_commit", "before": expected, "after": resulting,
                           "delivery": "unknown"}
                try:
                    pending = self.archive.append_intent(
                        self.producer, request_id, canonical(event), predecessor=head,
                        deadline_ms=self.archive.now() + 5000, expected=expected,
                    )
                except ArchiveConflict as error:
                    raise ArchiveUnavailable("archive position changed during operation") from error
                context["pending"] = pending
                outcome_schema(outcome, pending)
                sequence, tag = guard.record(db, dict(
                    node=self.node, actor=actor, role=role, action=action,
                    target=guard.audit_target(db, action, target),
                    credential_ref=guard.credential_reference(token)
                    if identity else None,
                    timestamp=time.time(), allowed=result["allowed"],
                    decision="allow" if result["allowed"] else "deny", reason=result["reason"],
                    request_id=request_id, version=result.get("version", version),
                ))
                marker = {"operation_id": request_id, "pending_tag": pending["tag"],
                          "request_id": request_id, "node": self.node, "position": [sequence, tag],
                          "outcome": outcome, "binding": binding,
                          "result": {key: result[key] for key in ("allowed", "reason", "version")
                                     if key in result}}
                raw = canonical(marker)
                db.execute(f"INSERT INTO {MARKER_TABLE} VALUES(?,?,?)",
                           (pending["tag"], raw, self.marker_proof(raw)))
                if event["kind"] == "revocation" and result["allowed"] and expected != resulting:
                    if guard.witness is not None:
                        guard.witness.advance(sequence, tag)
                rotated = result["reason"] == "version_rotated"
                if rotated:
                    guard.checkpoint("pre")
            if rotated:
                guard.checkpoint("committed")
            with guard.transaction(write=False, archive=True) as db:
                with self.archive.verified(write=False) as (_, records, _, initial):
                    _, _, committed = self.verify(db, records, initial, recover_pending=True)
                    if committed != marker:
                        raise ArchiveUnavailable("working commit could not be verified")
                self.archive.finalize(self.producer, pending["tag"], outcome)
                with self.archive.verified(write=False) as (_, records, _, initial):
                    self.verify(db, records, initial)
                if action == "evidence" and result["allowed"]:
                    result["evidence"] = render(evidence) if render else evidence
                if action == "enroll" and result["allowed"]:
                    result["device_ref"] = event["entity_id"]
        if rotated:
            guard.checkpoint("post")
        if result["reason"] == "revoked":
            result["commit_observed_ns"] = time.monotonic_ns()
        return result

    def prepare_event(self, action, target, approval, token, actor, result, before, after):
        kind = WORKER_ACTIONS[action]
        allowed = result["allowed"]
        target_ref = reference(target)
        keys = set()
        caller_ref = self.guard.digest(token) if actor is not None else None
        if caller_ref is not None:
            keys.add(("credential", caller_ref))
        metadata = {"credential_id": caller_ref} if caller_ref is not None else {}
        if action == "read":
            metadata["resource_present"] = ("asset", target_ref) in before
            if not metadata["resource_present"]:
                target_ref = "sha256-" + digest(target.encode())
            keys.update((("asset", target_ref), ("grant", target_ref)))
        elif action == "rotate":
            if ("asset", target_ref) not in before:
                target_ref = "sha256-" + digest(target.encode())
            keys.add(("asset", target_ref))
            if approval is not None:
                approval_ref = digest(approval.encode())
                keys.add(("approval", approval_ref))
            if allowed:
                metadata["approval_id"] = approval_ref
        elif action == "revoke":
            state = before.get(("credential", target_ref))
            if state is None:
                target_ref = "sha256-" + digest(target.encode())
            keys.add(("credential", target_ref))
        elif action == "enroll" and allowed:
            target_ref = self.guard.digest(result["token"])
            keys.add(("credential", target_ref))
        if action in {"enroll", "evidence"} and not allowed:
            target_ref = "sha256-" + digest(target.encode())
        event = {"version": 2, "event_id": result["request_id"], "request_id": result["request_id"],
                 "actor": reference(actor) if actor is not None else "anonymous",
                 "node": self.node, "subsystem": "worker", "kind": kind, "entity_id": target_ref,
                 "authorization": "allow" if allowed else "deny", "reason": result["reason"],
                 "received_ms": self.archive.now(), "source_ids": [], **metadata}
        if any(before.get(key) != after.get(key) for key in before.keys() | after.keys() if key not in keys):
            raise ArchiveUnavailable("unbound working-state change")
        return event, keys

    def pending_outcome(self, db, records, initial, pending_tag):
        self.archive.pending_record(records, pending_tag)
        _, _, marker = self.verify(db, records, initial, recover_pending=True)
        if marker is None or marker["pending_tag"] != pending_tag:
            raise ArchiveUnavailable("unresolved operation: verified commit evidence missing")
        return marker["outcome"]

    def authorize_recovery(self, principal, pending_tag, token, *, expires_ms):
        """Trusted offline authorization for a verified committed operation."""
        with store_lock(self.directory), self.guard.transaction(write=False, archive=True) as db:
            with self.archive.verified(write=False) as (_, records, _, initial):
                outcome = self.pending_outcome(db, records, initial, pending_tag)
            self.archive.grant_recovery(token, principal, pending_tag, outcome, expires_ms)

    def recover(self, token, pending_tag):
        with store_lock(self.directory), self.guard.transaction(write=False, archive=True) as db:
            with self.archive.verified(write=False) as (_, records, _, initial):
                terminal = next((r for r in records if r.get("pending_tag") == pending_tag), None)
                if terminal is None:
                    outcome = self.pending_outcome(db, records, initial, pending_tag)
                else:
                    self.verify(db, records, initial)
                    outcome = terminal["outcome"]
            terminal = self.archive.recover(token, pending_tag, outcome)
            with self.archive.verified(write=False) as (_, records, _, initial):
                self.verify(db, records, initial)
            return terminal

    def verify_asset_ciphertexts(self, db):
        """Authenticate every asset without exporting its decrypted contents."""
        for name, body, version in db.execute("SELECT id,body,version FROM files"):
            remaining = deadline.get()
            if remaining is not None and time.monotonic() >= remaining:
                raise ArchiveUnavailable("asset verification timed out")
            self.guard.decrypt(name, version, body)

    @staticmethod
    def copy_snapshot(source, destination):
        end = deadline.get()

        def check_progress(_status, _remaining, _total):
            if time.monotonic() >= end:
                raise ArchiveUnavailable("verified snapshot copy timed out")

        remaining = end - time.monotonic()
        if remaining <= 0:
            raise ArchiveUnavailable("verified snapshot copy timed out")
        with closing(sqlite3.connect(destination.as_uri() + "?mode=rw", uri=True,
                                     timeout=remaining)) as copy:
            copy.execute("PRAGMA synchronous=FULL")
            source.backup(copy, pages=100, progress=check_progress, sleep=0.01)

    def publish_snapshot(self, source, destination):
        with tempfile.TemporaryDirectory(prefix=".devforge-snapshot-", dir=destination.parent) as tmp:
            staged = Path(tmp) / "snapshot.sqlite"
            private_write(staged, b"")
            self.copy_snapshot(source, staged)
            os.link(staged, destination)
            fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)

    def export_verified(self, snapshot):
        """Publish a private, complete encrypted working snapshot without replacing a file."""
        destination = Path(snapshot).absolute()
        if os.path.lexists(destination):
            raise FileExistsError(destination)
        with store_lock(self.directory), self.guard.transaction(write=False, archive=True) as db:
            with self.archive.verified(write=False) as (_, records, _, initial):
                self.verify(db, records, initial)
                self.verify_asset_ciphertexts(db)
            self.publish_snapshot(db, destination)

    def restore_verified(self, snapshot):
        """Restore a snapshot only if it matches the current retained state."""
        self.guard.require_mode(archive=True)
        source = Path(snapshot).resolve()
        destination = Path(self.guard.path).resolve()
        if source == destination:
            raise ArchiveConflict("snapshot and working store must be distinct")
        with store_lock(self.directory), transaction(source.as_uri() + "?mode=ro", write=False, uri=True) as db:
            if self.guard.witness is not None:
                self.guard.witness.check(db)
            with self.archive.verified(write=False) as (_, records, _, initial):
                self.verify(db, records, initial)
                self.verify_asset_ciphertexts(db)
            if os.path.lexists(destination):
                self.copy_snapshot(db, destination)
            else:
                if any(os.path.lexists(str(destination) + suffix) for suffix in ("-wal", "-shm", "-journal")):
                    raise ArchiveUnavailable("missing working database has SQLite sidecars")
                self.publish_snapshot(db, destination)
