from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import secrets
import tempfile
import time
import unittest

from demo_cli import run
from kig_core.guard import Guard


class DemoTest(unittest.TestCase):
    def test_both_real_process_kills(self):
        for phase, version in (("pre", 1), ("post", 2)):
            with self.subTest(phase=phase):
                result = run(phase)
                self.assertEqual(result["active_version"], version)
                self.assertTrue(result["audit_verified"])
                self.assertEqual([entry["source"] for entry in result["timeline"]
                                  if entry["label"] == "ML-DSA-65 revocation evidence authenticated"],
                                 ["A", "B"])
                self.assertEqual(result["continuity"]["prepared"]["reads"], 5)
                self.assertEqual(result["continuity"]["prepared"]["errors"], 0)
                if phase == "post":
                    self.assertEqual(result["continuity"]["committed"]["reads"], 5)
                else:
                    self.assertNotIn("committed", result["continuity"])
                self.assertEqual(sum(r["label"] == "Revocation survived restart"
                                     for r in result["timeline"]), 2)

    def test_racing_rotations_and_audit_integrity(self):
        with tempfile.TemporaryDirectory() as directory:
            guard = Guard(Path(directory) / "test.sqlite", *[secrets.token_bytes(32) for _ in range(3)])
            admin = guard.enroll("operator", "admin")
            guard.seed_file("file", b"test", "operator")
            approvals = [guard.approve_rotation("operator", "file", 1, time.time() + 60)
                         for _ in range(2)]
            with ThreadPoolExecutor(2) as pool:
                results = list(pool.map(lambda approval: guard.execute(
                    "A", admin, "rotate", "file", version=1, approval=approval), approvals))
            self.assertEqual(sorted(result["reason"] for result in results),
                             ["version_rotated", "wrong_version"])
            guard.execute("A", admin, "read", "newline\nactor=other", version=1)
            self.assertEqual(guard.evidence(admin)[-1]["actor"], "operator")
            with guard.transaction() as db:
                db.execute("UPDATE audit SET event='{}' WHERE id=1")
                with self.assertRaises(ValueError):
                    guard.audit(db)
                db.rollback()
            with guard.transaction() as db:
                db.execute("DELETE FROM audit WHERE id=(SELECT MAX(id) FROM audit)")
            with self.assertRaises(ValueError):
                guard.evidence(admin)
