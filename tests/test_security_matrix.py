from contextlib import ExitStack, closing
import base64
import json
from pathlib import Path
import secrets
import sqlite3
import tempfile
import time
import unittest

from demo_cli import call, start
from kig_core.guard import Guard
from kig_core.judge import dispatch
from kig_core.witness import RevocationWitness
from kig_core.worker_archive import provision_archive


class SecurityMatrix(unittest.TestCase):
    def fixture(self, *, archive=False):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        keys = [secrets.token_bytes(32) for _ in range(3)]
        for name, key in zip(("audit", "storage", "backup"), keys):
            (root / f"{name}.key").write_bytes(key)
        (root / "attestation-A.key").write_bytes(secrets.token_bytes(32))
        (root / "witness").mkdir()
        witness = RevocationWitness(root / "witness" / "checkpoint.sqlite", keys[0])
        witness.provision()
        guard = Guard(root / "demo.sqlite", *keys, witness=witness)
        operator = guard.enroll("operator", "admin")
        another_operator = guard.enroll("other-operator", "admin")
        reader = guard.enroll("reader")
        guard.seed_file("brief", b"synthetic protected plaintext", "reader")
        guard.seed_file("notes", b"unrelated file", "other-reader")
        approved = guard.approve_rotation("operator", "brief", 1, time.time() + 60)
        expired = guard.approve_rotation("operator", "brief", 1, time.time() - 60)
        if archive:
            provision_archive(root, guard)
        return root, guard, operator, another_operator, reader, approved, expired

    def test_baseline_audit_does_not_attest_current_grant(self):
        _, guard, operator, _, reader, _, _ = self.fixture()
        self.assertTrue(guard.execute("A", reader, "read", "brief", version=1)["allowed"])
        before = guard.evidence(operator)
        with guard.transaction() as db:
            db.execute("DELETE FROM grants WHERE actor=? AND file=?", ("reader", "brief"))
        self.assertEqual(before, guard.evidence(operator))
        self.assertFalse(guard.execute("B", reader, "read", "brief", version=1)["allowed"])

    def test_baseline_audit_scope_for_other_persisted_rows(self):
        for table, column in (("devices", "token"), ("approvals", "id"), ("files", "id")):
            with self.subTest(table=table):
                _, guard, operator, _, reader, approval, _ = self.fixture()
                before = guard.evidence(operator)
                value = {"devices": guard.digest(reader), "approvals": approval, "files": "brief"}[table]
                with guard.transaction() as db:
                    deleted = db.execute(f"DELETE FROM {table} WHERE {column}=?", (value,))
                    self.assertEqual(deleted.rowcount, 1)
                self.assertEqual(before, guard.evidence(operator))

    def test_protected_routes_authentication_and_role_matrix(self):
        for archive in (False, True):
            with self.subTest(archive=archive), ExitStack() as stack:
                root, guard, admin, _, reader, approved, _ = self.fixture(archive=archive)
                port, _ = start(stack, root, "A", root / "node.log", archive=archive)
                status, allowed, _ = call(port, "read", reader, {"target": "brief", "version": 1})
                self.assertEqual(status, 200)
                evidence = f"evidence/{allowed['request_id']}"
                tests = (
                    ("read", {"target": "notes", "version": 1}),
                    ("rotate", {"target": "brief", "version": 1, "approval": approved}),
                    ("revoke", {"target": guard.digest(reader)}),
                    ("enroll", {"target": "reader"}),
                    (evidence, None),
                    (evidence + "/attestation", {"challenge": "a" * 64}),
                )
                for index, (route, fields) in enumerate(tests):
                    for token, expected in (("", 401), (reader, 403)):
                        with self.subTest(route=route, status=expected):
                            key = f"auth-{index}-{expected}"
                            status, result, _ = call(port, route, token, fields, idempotency_key=key)
                            self.assertEqual(status, expected)
                            self.assertTrue({"body", "token", "proof", "signature"}.isdisjoint(result))
                self.assertEqual(call(port, evidence, admin)[0], 200)
                self.assertEqual(call(port, evidence + "/attestation", admin, {"challenge": "a" * 64})[0], 200)

    def test_approval_binding_expiry_and_consumption(self):
        for archive in (False, True):
            with self.subTest(archive=archive), ExitStack() as stack:
                root, _, admin, other, reader, approved, expired = self.fixture(archive=archive)
                ports = [start(stack, root, node, root / (node + ".log"), archive=archive)[0]
                         for node in ("A", "B")]
                checks = (
                    (other, "brief", 1, approved, "approval_actor_mismatch"),
                    (admin, "notes", 1, approved, "approval_target_mismatch"),
                    (admin, "brief", 2, approved, "approval_version_mismatch"),
                    (admin, "brief", 1, expired, "approval_expired"),
                    (admin, "brief", 1, approved, "version_rotated"),
                    (admin, "brief", 1, approved, "approval_missing"),
                )
                for index, (token, target, version, approval, reason) in enumerate(checks):
                    status, result, _ = call(
                        ports[index % 2], "rotate", token, dict(target=target, version=version, approval=approval),
                        idempotency_key=f"rotation-{index}",
                    )
                    self.assertEqual(status, 200 if reason == "version_rotated" else 403)
                    self.assertEqual(result["reason"], reason)
                for port in ports:
                    status, result, _ = call(port, "read", reader, {"target": "brief", "version": 1})
                    self.assertEqual((status, result["reason"]), (403, "wrong_version"))

    def test_bounded_structured_audit_redacts_untrusted_input(self):
        for archive in (False, True):
            with self.subTest(archive=archive), ExitStack() as stack:
                root, guard, _, _, reader, approved, _ = self.fixture(archive=archive)
                port, _ = start(stack, root, "A", root / "node.log", archive=archive)
                injected = reader + '\r\n{"actor":"spoof"}\t\x1b'
                status, denial, _ = call(port, "read", reader, {"target": injected, "version": 1})
                self.assertEqual((status, denial["reason"]), (403, "missing_grant"))
                status, invalid, _ = call(port, "read", reader, {"target": reader * 8, "version": 1})
                self.assertEqual((status, invalid), (422, {"error": "invalid_request"}))
                status, invalid, _ = call(port, "read", reader, {"target": [], "version": "1"})
                self.assertEqual((status, invalid), (422, {"error": "invalid_request"}))
                status, invalid, _ = call(port, "rotate", reader, {"target": "brief", "version": 2**80},
                                          idempotency_key="version-overflow")
                self.assertEqual((status, invalid), (422, {"error": "invalid_request"}))
                if archive:
                    status, invalid, _ = call(port, "rotate", reader, {"target": "brief"}, idempotency_key="space key")
                    self.assertEqual((status, invalid), (422, {"error": "invalid_request"}))
                with closing(sqlite3.connect(guard.path)) as db:
                    rows = db.execute("SELECT event FROM audit").fetchall()
                self.assertEqual(len(rows), 1)
                raw = rows[0][0]
                event = json.loads(raw)
                self.assertEqual(event["actor"], "reader")
                self.assertEqual(event["request_id"], denial["request_id"])
                self.assertEqual(event["decision"], "deny")
                for value in ("\r", "\n", "\t", "\x1b", "spoof", reader, approved, "synthetic protected plaintext",
                              base64.b64encode((root / "attestation-A.key").read_bytes()).decode()):
                    self.assertNotIn(value, raw)

    def test_ciphertext_and_authenticated_audit_fail_closed(self):
        for malformed in ("ciphertext", "audit"):
            with self.subTest(malformed=malformed), ExitStack() as stack:
                root, guard, _, _, reader, _, _ = self.fixture()
                port, _ = start(stack, root, "A", root / "node.log")
                fields = {"target": "brief", "version": 1}
                self.assertEqual(call(port, "read", reader, fields)[0], 200)
                with closing(sqlite3.connect(guard.path)) as db, db:
                    if malformed == "audit":
                        db.execute("UPDATE audit SET event='{}' WHERE id=1")
                    else:
                        db.execute("UPDATE files SET body=zeroblob(length(body)) WHERE id='brief'")
                status, failure, _ = call(port, "read", reader, fields)
                self.assertEqual((status, failure), (503, {"error": "verification_failed"}))
                with closing(sqlite3.connect(guard.path)) as db:
                    self.assertEqual(db.execute("SELECT count(*) FROM audit").fetchone()[0], 1)

    def test_organizer_duplicate_id_preserves_original_decision(self):
        path = Path(self.enterContext(tempfile.TemporaryDirectory())) / "judge.sqlite"
        dispatch(path, {"op": "setup", "owners": {"brief": "reader"},
                        "contents": {"brief": "synthetic"}, "disabled": []})
        read = {"op": "read", "actor": "reader", "asset": "brief", "request_id": "event-1"}
        self.assertEqual(dispatch(path, read)["decision"], "allow")
        self.assertEqual(dispatch(path, {**read, "actor": "other"}), {"decision": "deny"})
        dispatch(path, {"op": "revoke", "actor": "reader"})
        self.assertEqual(dispatch(path, read), {"decision": "deny"})
        self.assertEqual(dispatch(path, {"op": "audit", "request_id": "event-1"})["decision"], "allow")
