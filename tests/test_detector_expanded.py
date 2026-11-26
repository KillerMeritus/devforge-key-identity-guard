import unittest

from kig_core.detector import analyze
from scripts.expanded_detector_fixture import BLOCKS, generate


class ExpandedDetectorTest(unittest.TestCase):
    def test_expanded_replay_against_scenario_authored_labels(self):
        fixture = generate()
        self.assertGreaterEqual(len(fixture["benign_event_ids"]), 1_000)
        alerts, notes = analyze(fixture["events"], fixture["approvals"])
        self.assertEqual({(item["anchor_event_id"], item["rule"]) for item in alerts},
                         {(item["event_id"], item["rule"]) for item in fixture["expected"]})
        self.assertEqual(len(alerts), len(fixture["expected"]))
        conflict_notes = {note["event"] for note in notes if note["reason"] == "conflicting_event_identity"}
        contested = set(fixture["contested_event_ids"])
        self.assertEqual(conflict_notes, contested)
        self.assertTrue(all(contested.isdisjoint(item["evidence_event_ids"]) for item in alerts))
        self.assertEqual(sum(note["reason"] == "order_uncertain" for note in notes), BLOCKS)
        self.assertEqual(sum(note["reason"] == "arrival_outside_window" for note in notes), BLOCKS)

    def test_conflicting_event_id_is_excluded_in_either_arrival_order(self):
        fixture = generate()
        identity = fixture["contested_event_ids"][0]
        contested = [event for event in fixture["events"] if event["event_id"] == identity]
        self.assertEqual(len(contested), 2)
        for pair in (contested, contested[::-1]):
            with self.subTest(first=pair[0]["outcome"]):
                alerts, notes = analyze(pair, [])
                self.assertEqual(alerts, [])
                self.assertEqual(notes, [{"event": identity, "reason": "conflicting_event_identity"}])
