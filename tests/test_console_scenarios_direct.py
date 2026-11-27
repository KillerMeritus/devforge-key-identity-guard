"""Exercise the lab runner independently of browser presentation."""
import unittest

from console_scenarios import assurance_lab


class ScenarioRunnerTests(unittest.TestCase):
    def test_approval_scenarios_and_independent_runs(self):
        first = assurance_lab("approval")["observations"]
        second = assurance_lab("approval")["observations"]
        before_ids = {item["request_id"] for item in first["outcomes"]}
        after_ids = {item["request_id"] for item in second["outcomes"]}
        self.assertTrue(before_ids.isdisjoint(after_ids))
        self.assertEqual([row["reason"] for row in first["evidence"]],
                         ["approval_expired", "version_rotated", "approval_missing"])
        competing = assurance_lab("competing")["observations"]
        self.assertEqual(sorted(row["status"] for row in competing["outcomes"]), [200, 403])

    def test_backup_and_passport_return_actual_negative_results(self):
        backup = assurance_lab("backup")["observations"]
        self.assertTrue(backup["intact_accepted"])
        self.assertFalse(backup["damaged_accepted"])
        self.assertEqual([row["allowed"] for row in backup["audit_records"]], [True, False])
        passport = assurance_lab("passport", "ca" * 32)
        self.assertEqual(set(passport["claims"].values()), {"VERIFIED"})
        for observation in passport["observations"].values():
            self.assertEqual(observation["modified"], "REJECTED")
            self.assertEqual(observation["challenge"], "ca" * 32)
