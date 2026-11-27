import json
from pathlib import Path
import unittest

from kig_core.detector import analyze


class FrozenDetectorBoundaryTest(unittest.TestCase):
    def test_manual_labels_include_uncertainty_and_unrelated_controls(self):
        path = Path(__file__).parent / "fixtures" / "detector-boundaries.json"
        fixture = json.loads(path.read_text())
        findings, notes = analyze(fixture["events"], fixture["approvals"])
        self.assertCountEqual(
            [(row["anchor_event_id"], row["rule"], row["classification"]) for row in findings],
            [(row["event_id"], row["rule"], row["classification"]) for row in fixture["expected"]],
        )
        self.assertCountEqual(
            [(row["event"], row["reason"]) for row in notes],
            [(row["event"], row["reason"]) for row in fixture["expected_notes"]],
        )
        self.assertTrue({row["anchor_event_id"] for row in findings}.isdisjoint(fixture["benign_event_ids"]))
