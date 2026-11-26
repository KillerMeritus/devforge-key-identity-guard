from contextlib import ExitStack, closing
import os
from pathlib import Path
import secrets
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from demo_cli import call, start
from kig_core.guard import Guard
from kig_core.witness import RevocationWitness


def copy_database(source, destination):
    with closing(sqlite3.connect(source)) as original, closing(sqlite3.connect(destination)) as copied:
        original.backup(copied)


class RollbackTest(unittest.TestCase):
    def setUp(self):
        self.state = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.path = self.state / "demo.sqlite"
        self.checkpoint = self.state / "witness" / "checkpoint.sqlite"
        self.checkpoint.parent.mkdir()
        self.keys = [secrets.token_bytes(32) for _ in range(3)]
        for name, key in zip(("audit", "storage", "backup"), self.keys):
            (self.state / f"{name}.key").write_bytes(key)
        self.witness = RevocationWitness(self.checkpoint, self.keys[0])
        self.witness.provision()
        self.guard = Guard(self.path, *self.keys, witness=self.witness)
        self.admin = self.guard.enroll("operator", "admin")
        self.laptop = self.guard.enroll("owner")
        self.teammate = self.guard.enroll("teammate")
        self.guard.seed_file("brief", b"synthetic", "owner", "teammate")

    def test_pre_revocation_snapshot_is_blocked_by_both_nodes(self):
        fields = {"target": "brief", "version": 1}
        original = self.state / "before.sqlite"
        current = self.state / "after.sqlite"
        with ExitStack() as stack:
            a, _ = start(stack, self.state, "A", self.state / "before.log")
            self.assertEqual(call(a, "read", self.laptop, fields)[0], 200)
            copy_database(self.path, original)
            status, revoked, _ = call(a, "revoke", self.admin,
                                      {"target": self.guard.digest(self.laptop)})
            self.assertEqual(status, 200)
            self.assertEqual(call(a, "read", self.laptop, fields)[1]["reason"], "revoked_device")
            self.assertEqual(call(a, "read", self.teammate, fields)[0], 200)
        copy_database(self.path, current)
        copy_database(original, self.path)
        with ExitStack() as stack:
            for node in ("A", "B"):
                port, _ = start(stack, self.state, node, self.state / f"stale-{node}.log")
                for token in (self.laptop, self.teammate):
                    status, body, _ = call(port, "read", token, fields)
                    self.assertEqual((status, body), (503, {"error": "verification_failed"}))
                route = f"evidence/{revoked['request_id']}/attestation"
                self.assertEqual(call(port, route, self.admin,
                                      {"challenge": secrets.token_hex(32)})[0], 503)
        copy_database(current, self.path)
        with ExitStack() as stack:
            for node in ("A", "B"):
                port, _ = start(stack, self.state, node, self.state / f"current-{node}.log")
                self.assertEqual(call(port, "read", self.teammate, fields)[0], 200)
                self.assertEqual(call(port, "read", self.laptop, fields)[1]["reason"], "revoked_device")

    @unittest.skipUnless(os.environ.get("TRACK4_ARCHIVE_ACCEPTANCE") == "1",
                         "archive enforcement is pending")
    def test_post_revocation_restore_with_later_evidence_is_blocked(self):
        fields = {"target": "brief", "version": 1}
        original = self.state / "after-revocation.sqlite"
        current = self.state / "with-later-evidence.sqlite"
        nodes = ("A", "B")
        for node in nodes:
            (self.state / f"attestation-{node}.key").write_bytes(secrets.token_bytes(32))

        with ExitStack() as stack:
            ports = {node: start(stack, self.state, node, self.state / f"{node}.log")[0]
                     for node in nodes}
            status, _, _ = call(ports["A"], "revoke", self.admin,
                                {"target": self.guard.digest(self.laptop)})
            self.assertEqual(status, 200)
            denials = {}
            for node, port in ports.items():
                status, denial, _ = call(port, "read", self.laptop, fields)
                self.assertEqual(status, 403)
                self.assertEqual(denial["reason"], "revoked_device")
                denials[node] = denial["request_id"]
            copy_database(self.path, original)
            status, later, _ = call(ports["B"], "rotate", self.teammate, fields)
            self.assertEqual(status, 403)
            self.assertEqual(later["reason"], "action_forbidden")
            preserved_event = f"evidence/{later['request_id']}"
            self.assertEqual(call(ports["B"], preserved_event, self.admin)[0], 200)

        copy_database(self.path, current)
        copy_database(original, self.path)
        with ExitStack() as stack:
            for node in nodes:
                port, _ = start(stack, self.state, node, self.state / f"stale-{node}.log")
                with self.subTest(node=node, operation="authorized read"):
                    status, body, _ = call(port, "read", self.teammate, fields)
                    self.assertEqual(status, 503)
                    self.assertNotIn("body", body)
                with self.subTest(node=node, operation="fresh signature"):
                    status, body, _ = call(
                        port, f"evidence/{denials[node]}/attestation", self.admin,
                        {"challenge": secrets.token_hex(32)},
                    )
                    self.assertEqual(status, 503)
                    self.assertNotIn("signature", body)

        copy_database(current, self.path)
        with ExitStack() as stack:
            for node in nodes:
                with self.subTest(node=node, operation="verified current restore"):
                    port, _ = start(stack, self.state, node, self.state / f"current-{node}.log")
                    self.assertEqual(call(port, "read", self.teammate, fields)[0], 200)
                    self.assertEqual(call(port, "read", self.laptop, fields)[1]["reason"],
                                     "revoked_device")
                    self.assertEqual(call(port, preserved_event, self.admin)[0], 200)

    def test_missing_witness_is_unavailable_and_never_recreated(self):
        with ExitStack() as stack:
            port, _ = start(stack, self.state, "A", self.state / "node.log")
            self.checkpoint.rename(self.state / "checkpoint-saved.sqlite")
            status, body, _ = call(port, "read", self.laptop, {"target": "brief", "version": 1})
            self.assertEqual((status, body), (503, {"error": "state_unavailable"}))
            self.assertFalse(self.checkpoint.exists())

    def test_interrupted_revocation_after_checkpoint_fails_closed(self):
        real_advance = self.witness.advance

        def interrupt(sequence, tag):
            real_advance(sequence, tag)
            raise RuntimeError("simulated failure before the local commit")

        with patch.object(self.witness, "advance", side_effect=interrupt):
            with self.assertRaisesRegex(RuntimeError, "simulated failure"):
                self.guard.execute("A", self.admin, "revoke", self.guard.digest(self.laptop))
        with self.assertRaisesRegex(ValueError, "revocation checkpoint"):
            self.guard.execute("B", self.laptop, "read", "brief", version=1)

    def test_changed_checkpoint_cannot_authorize_reads(self):
        with closing(sqlite3.connect(self.checkpoint)) as db, db:
            db.execute("UPDATE checkpoint SET sequence=1")
        with self.assertRaisesRegex(ValueError, "invalid revocation checkpoint"):
            self.guard.execute("A", self.laptop, "read", "brief", version=1)
