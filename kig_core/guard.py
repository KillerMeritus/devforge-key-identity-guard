"""Local defensive prototype. Two workers share a transactional authority."""
import base64
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import time

from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


from .db import enable_wal, transaction


ARCHIVE_MODE_FILE = "archive.required"
ARCHIVE_MODE = b"devforge-archive-v1\n"


class Guard:
    def __init__(self, path, audit_key, storage_key, backup_key=None, checkpoint=None, *, witness=None,
                 bootstrap=True):
        self.path = path
        self.audit_key = audit_key
        self.storage_key = storage_key
        self.backup_key = backup_key
        self.witness = witness
        self.checkpoint = checkpoint or (lambda _: None)
        self.existing_only = not bootstrap
        if self.existing_only or self.archive_reserved():
            return
        enable_wal(path)
        with transaction(self.path) as db:
            for ddl in (
                "devices(token TEXT PRIMARY KEY, actor TEXT, role TEXT, revoked INTEGER DEFAULT 0)",
                "files(id TEXT PRIMARY KEY, body BLOB, version INTEGER)",
                "grants(actor TEXT, file TEXT, PRIMARY KEY(actor,file))",
                "approvals(id TEXT PRIMARY KEY, actor TEXT, target TEXT, version INTEGER, expires REAL)",
                "audit(id INTEGER PRIMARY KEY, event TEXT, tag TEXT)",
                "audit_head(singleton INTEGER PRIMARY KEY CHECK(singleton=1), seq INTEGER, tag TEXT, proof TEXT)",
            ):
                db.execute("CREATE TABLE IF NOT EXISTS " + ddl)

    def archive_reserved(self):
        state = Path(self.path).resolve().parent
        return any(os.path.lexists(state / name) for name in (ARCHIVE_MODE_FILE, "archive"))

    def require_mode(self, *, archive):
        if archive:
            marker = Path(self.path).resolve().parent / ARCHIVE_MODE_FILE
            try:
                mode = marker.read_bytes()
            except FileNotFoundError as error:
                # Older archived fixtures already reserved this external directory.
                if not os.path.lexists(marker) and (marker.parent / "archive").is_dir():
                    return
                raise ValueError("archive execution mode binding unavailable") from error
            except OSError as error:
                raise ValueError("archive execution mode binding unavailable") from error
            if mode != ARCHIVE_MODE:
                raise ValueError("invalid archive execution mode binding")
        elif self.archive_reserved():
            raise ValueError("archive enforcement required for this state directory")

    @contextmanager
    def transaction(self, *, write=True, archive=False, on_rollback=None):
        path = self.path
        if self.existing_only:
            path = Path(path).resolve().as_uri() + ("?mode=rw" if write else "?mode=ro")
        with transaction(path, write=write, uri=self.existing_only, on_rollback=on_rollback) as db:
            self.require_mode(archive=archive)
            if self.witness is not None:
                self.witness.check(db)
            yield db

    def enroll(self, actor, role="reader"):
        """Trusted provisioning entry point."""
        token = secrets.token_urlsafe(32)
        with self.transaction() as db:
            db.execute("INSERT INTO devices(token,actor,role) VALUES(?,?,?)",
                       (self.digest(token), actor, role))
        return token

    @staticmethod
    def digest(token):
        return hashlib.sha256(token.encode()).hexdigest()

    def file_cipher(self, file, version):
        context = json.dumps([file, version]).encode()
        return AESGCM(self.file_key(context)), context

    def file_key(self, context):
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=b"devforge-file:" + context).derive(self.storage_key)

    def encrypt(self, file, version, body):
        cipher, context = self.file_cipher(file, version)
        nonce = secrets.token_bytes(12)
        return nonce + cipher.encrypt(nonce, body, context)

    def decrypt(self, file, version, encrypted):
        cipher, context = self.file_cipher(file, version)
        return cipher.decrypt(encrypted[:12], encrypted[12:], context)

    def seed_file(self, file, body, *actors):
        """Trusted fixture provisioning entry point."""
        encrypted = self.encrypt(file, 1, body)
        with self.transaction() as db:
            db.execute("INSERT INTO files VALUES(?,?,1)", (file, encrypted))
            db.executemany("INSERT INTO grants VALUES(?,?)", [(actor, file) for actor in actors])

    def approve_rotation(self, actor, target, version, expires):
        """Trusted approval issuer. Each approval is single-use."""
        approval = secrets.token_urlsafe(24)
        with self.transaction() as db:
            db.execute("INSERT INTO approvals VALUES(?,?,?,?,?)",
                       (approval, actor, target, version, expires))
        return approval

    def tag(self, previous, event):
        return hmac.digest(self.audit_key, previous.encode() + event.encode(), "sha256").hex()

    def execute(self, node, token, action, target, *, version=None, approval=None,
                public_key=None, challenge=None):
        prepared = None
        if action == "rotate" and type(version) is int:
            with self.transaction(write=False) as db:
                identity = self.identity(db, token)
                if identity and identity[1:] == ("admin", 0):
                    row = db.execute("SELECT body FROM files WHERE id=? AND version=?",
                                     (target, version)).fetchone()
                    if row:
                        prepared = row[0]
            if prepared is not None:
                prepared = self.encrypt(target, version + 1, self.decrypt(target, version, prepared))
                self.checkpoint("prepared")

        with self.transaction() as db:
            identity = self.identity(db, token)
            actor, role, revoked = identity or (None, None, False)
            result = {"allowed": False, "reason": "invalid_device"}
            if revoked:
                result["reason"] = "revoked_device"
            elif identity:
                result = self.apply(db, actor, role, action, target, version,
                                    approval, public_key, challenge, prepared)
            result["request_id"] = secrets.token_hex(16)
            sequence, tag = self.record(db, dict(node=node, actor=actor, role=role, action=action,
                                 target=target, timestamp=time.time(), allowed=result["allowed"],
                                 decision="allow" if result["allowed"] else "deny",
                                 reason=result["reason"], request_id=result["request_id"],
                                 version=result.get("version", version)))
            if result["reason"] == "revoked" and self.witness is not None:
                # Persist the independent checkpoint before acknowledging the revocation.
                # A crash before the local commit then fails closed on the next request.
                self.witness.advance(sequence, tag)
            rotated = result["reason"] == "version_rotated"
            if rotated:
                self.checkpoint("pre")
        if rotated:
            self.checkpoint("post")
        if result["reason"] == "revoked":
            result["commit_observed_ns"] = time.monotonic_ns()
        return result

    def identity(self, db, token):
        return db.execute("SELECT actor,role,revoked FROM devices WHERE token=?",
                          (self.digest(token),)).fetchone()

    def record(self, db, event):
        event = json.dumps(event, sort_keys=True, separators=(",", ":"))
        head = db.execute("SELECT seq,tag,proof FROM audit_head WHERE singleton=1").fetchone()
        index, previous = 0, ""
        if head:
            index, previous, proof = head
            if not hmac.compare_digest(proof, self.head_proof(index, previous)):
                raise ValueError("invalid audit head")
        tag = self.tag(previous, event)
        index += 1
        db.execute("INSERT INTO audit VALUES(?,?,?)", (index, event, tag))
        db.execute("INSERT OR REPLACE INTO audit_head VALUES(1,?,?,?)",
                   (index, tag, self.head_proof(index, tag)))
        return index, tag

    def head_proof(self, index, tag):
        return hmac.digest(self.audit_key, f"head:{index}:{tag}".encode(), "sha256").hex()

    def backup(self, file, version):
        context = json.dumps([file, version]).encode()
        with self.transaction(write=False) as db:
            active = db.execute("SELECT version FROM files WHERE id=?", (file,)).fetchone()
            if active != (version,):
                raise ValueError("ineligible version")
        nonce = secrets.token_bytes(12)
        return nonce + AESGCM(self.backup_key).encrypt(nonce, self.file_key(context), context)

    def verify_backup(self, file, version, backup, node):
        from cryptography.exceptions import InvalidTag

        context = json.dumps([file, version]).encode()
        with self.transaction() as db:
            active = db.execute("SELECT version FROM files WHERE id=?", (file,)).fetchone()
            valid = False
            if active == (version,):
                try:
                    recovered = AESGCM(self.backup_key).decrypt(backup[:12], backup[12:], context)
                    valid = hmac.compare_digest(recovered, self.file_key(context))
                except (InvalidTag, ValueError):
                    pass
            self.record(db, dict(node=node, actor="local-operator", action="verify_backup",
                                 target=file, version=version, timestamp=time.time(), allowed=valid,
                                 reason="verified_backup" if valid else "rejected_backup"))
        return valid

    def apply(self, db, actor, role, action, target, version, approval, public_key, challenge, prepared):
        def decision(reason, allowed=False, **data):
            return dict(allowed=allowed, reason=reason, **data)

        if action == "revoke" and role == "admin":
            changed = db.execute("UPDATE devices SET revoked=1 WHERE token=?", (target,)).rowcount
            return decision("revoked" if changed else "unknown_device", bool(changed))
        if action == "message":
            return decision("messaging_unsupported")
        if action == "enroll" and role == "admin":
            if not db.execute("SELECT 1 FROM grants WHERE actor=?", (target,)).fetchone():
                return decision("unknown_actor")
            token = secrets.token_urlsafe(32)
            db.execute("INSERT INTO devices(token,actor,role) VALUES(?,?,?)",
                       (self.digest(token), target, "reader"))
            return decision("enrolled", True, token=token)
        if action == "read":
            grant = db.execute("SELECT 1 FROM grants WHERE actor=? AND file=?",
                               (actor, target)).fetchone()
            if not grant:
                return decision("missing_grant")
            encrypted, current = db.execute("SELECT body,version FROM files WHERE id=?",
                                            (target,)).fetchone()
            if type(version) is not int or version != current:
                return decision("wrong_version")
            body = self.decrypt(target, current, encrypted)
            if public_key is None and challenge is None:
                return decision("read", True, body=base64.b64encode(body).decode())
            try:
                key = MLKEM768PublicKey.from_public_bytes(base64.b64decode(public_key, validate=True))
                if not isinstance(challenge, str):
                    raise ValueError("challenge must be text")
                shared, ciphertext = key.encapsulate()
            except (TypeError, ValueError):
                return decision("invalid_protected_read")
            proof = hmac.digest(shared, challenge.encode() + body, "sha256").hex()
            return decision("protected_read", True, ciphertext=base64.b64encode(ciphertext).decode(),
                            proof=proof)
        if action == "rotate" and role == "admin":
            record = db.execute("SELECT actor,target,version,expires FROM approvals WHERE id=?",
                                (approval,)).fetchone()
            if not record:
                return decision("approval_missing")
            for field, actual, expected in zip(("actor", "target", "version"),
                                               (actor, target, version), record[:3]):
                if actual != expected:
                    return decision("approval_" + field + "_mismatch")
            if time.time() >= record[3]:
                return decision("approval_expired")
            if type(version) is not int:
                return decision("wrong_version")
            if prepared is None:
                return decision("wrong_version")
            changed = db.execute("UPDATE files SET body=?,version=? WHERE id=? AND version=?",
                                 (prepared, version + 1, target, version)).rowcount
            if not changed:
                return decision("wrong_version")
            db.execute("DELETE FROM approvals WHERE id=?", (approval,))
            return decision("version_rotated", True, version=version + 1)
        return decision("action_forbidden")

    def audit(self, db):
        previous = ""
        events = []
        for expected, (index, event, tag) in enumerate(
            db.execute("SELECT id,event,tag FROM audit ORDER BY id"), start=1
        ):
            if index != expected or not hmac.compare_digest(self.tag(previous, event), tag):
                raise ValueError("Audit integrity check failed")
            events.append(dict(id=index, **json.loads(event)))
            previous = tag
        head = db.execute("SELECT seq,tag,proof FROM audit_head WHERE singleton=1").fetchone()
        if head or events:
            expected_head = (len(events), previous, self.head_proof(len(events), previous))
            if head is None or head[:2] != expected_head[:2] or not hmac.compare_digest(head[2], expected_head[2]):
                raise ValueError("Audit head mismatch")
        return events

    def evidence(self, token):
        with self.transaction(write=False) as db:
            identity = self.identity(db, token)
            if identity is None:
                raise PermissionError("unauthenticated")
            if identity[1:] != ("admin", 0):
                raise PermissionError("forbidden")
            return self.audit(db)
