import json
from pathlib import Path
import unittest

from kig_core.detector import analyze


class HeldOutDetectorTest(unittest.TestCase):
    def test_fixed_labels_and_conflicting_identity(self):
        fixture = json.loads((Path(__file__).parent / "fixtures/detector-heldout.json").read_text())
        findings, notes = analyze(fixture["events"], fixture["approvals"])
        self.assertEqual({(alert["anchor_event_id"], alert["rule"]) for alert in findings},
                         {(item["event_id"], item["rule"]) for item in fixture["expected"]})
        self.assertEqual({(item["event"], item["reason"]) for item in notes},
                         {(item["event"], item["reason"]) for item in fixture["expected_notes"]})
        for alert in findings:
            self.assertIsInstance(alert["rule_version"], int)
            self.assertTrue(alert["actor"] and alert["service_edges"] and alert["evidence_event_ids"])
            self.assertTrue(alert["explanation"])
            self.assertEqual(alert["uncertainty_ms"], 125)
        lateral = next(alert for alert in findings if alert["rule"] == "lateral_movement_candidate")
        self.assertEqual(lateral["classification"], "investigate")
        violation = next(alert for alert in findings if alert["rule"] == "access_outside_approval")
        self.assertEqual(violation["classification"], "policy_violation")
