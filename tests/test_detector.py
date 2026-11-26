import unittest

from detection_cli import benchmark, synthetic
from kig_core.detector import Detector, analyze


class DetectorTest(unittest.TestCase):
    def test_expiry_and_ambiguous_order(self):
        event = dict(event_id="change", event_time_utc="2026-01-15T09:00:00Z",
                     received_time_utc="2026-01-15T09:00:00.200Z",
                     source_clock_offset_ms=0, actor="user", source_service="portal",
                     target_service="identity", action="role_change", role_after="operator",
                     outcome="success", approval_id="approval", session_id="session",
                     correlation_id="flow")
        read = dict(event, event_id="read", action="read", target_service="catalog", outcome="allow",
                    event_time_utc="2026-01-15T09:00:00.100Z")
        approval = dict(approval_id="approval", subject="user", operation="grant_role", role="operator",
                        valid_from_utc="2026-01-15T08:00:00Z", valid_until_utc="2026-01-15T09:00:00Z")
        alerts, notes = analyze([read, event], [approval])
        self.assertEqual([item["rule"] for item in alerts], ["unexpected_role_change"])
        self.assertIn({"event": "read", "reason": "order_uncertain"}, notes)

    def test_arrival_emits_only_once_when_evidence_is_complete(self):
        events, approvals, _ = next(synthetic(repetitions=1))
        by_name = {event["event_id"].removeprefix("session-0-"): event for event in events}
        detector = Detector(approvals)
        self.assertEqual(detector.ingest(by_name["follow-up"]), ([], []))
        alerts, _ = detector.ingest(by_name["unexpected-grant"])
        self.assertEqual({alert["rule"] for alert in alerts},
                         {"unexpected_role_change", "review_after_role_change"})
        review = next(alert for alert in alerts if alert["rule"] == "review_after_role_change")
        self.assertEqual(review["evidence_event_ids"],
                         ["session-0-unexpected-grant", "session-0-follow-up"])
        self.assertEqual(detector.ingest(by_name["unexpected-grant"]), ([], []))
        self.assertEqual(detector.ingest(by_name["follow-up"]), ([], []))
        self.assertEqual(detector.finish(), [])

    def test_repeated_edge_is_not_an_unusual_path(self):
        events, approvals, _ = next(synthetic(repetitions=1))
        detector = Detector(approvals)
        first, second = [event for event in events if "-worker-hop-" in event["event_id"]]
        self.assertEqual(detector.ingest(first), ([], []))
        repeated = dict(first, event_id="same-edge")
        self.assertEqual(detector.ingest(repeated), ([], []))
        unrelated = dict(second, event_id="new-flow", correlation_id="unrelated")
        self.assertEqual(detector.ingest(unrelated), ([], []))
        alerts, _ = detector.ingest(second)
        self.assertEqual({alert["anchor_event_id"] for alert in alerts},
                         {first["event_id"], second["event_id"], "same-edge"})
        self.assertTrue(all(len(alert["evidence_event_ids"]) == 2 for alert in alerts))

    def test_late_change_cannot_supply_causal_evidence(self):
        events, approvals, _ = next(synthetic(repetitions=1))
        detector = Detector(approvals)
        read = next(event for event in events if event["event_id"].endswith("-follow-up"))
        change = next(event for event in events if event["event_id"].endswith("-unexpected-grant"))
        self.assertEqual(detector.ingest(read), ([], []))
        alerts, notes = detector.ingest(dict(change, received_time_utc="2026-01-15T09:00:12Z"))
        self.assertEqual([alert["rule"] for alert in alerts], ["unexpected_role_change"])
        self.assertEqual(notes, [{"event": change["event_id"], "reason": "arrival_outside_window"}])
        self.assertEqual([alert["rule"] for alert in detector.finish()], ["unexpected_allowed_access"])

    def test_earlier_read_with_overlapping_clock_ranges_is_uncertain(self):
        events, approvals, _ = next(synthetic(repetitions=1))
        read = next(event for event in events if event["event_id"].endswith("-follow-up"))
        change = next(event for event in events if event["event_id"].endswith("-unexpected-grant"))
        read = dict(read, event_time_utc="2026-01-15T09:00:02.100Z", target_service="catalog")
        for sequence in ([read, change], [change, read]):
            with self.subTest(first=sequence[0]["event_id"]):
                alerts, notes = analyze(sequence, approvals)
                self.assertEqual([alert["rule"] for alert in alerts], ["unexpected_role_change"])
                self.assertIn({"event": read["event_id"], "reason": "order_uncertain"}, notes)

    def test_synthetic_benchmark(self):
        result = benchmark()
        self.assertEqual(result["false_negatives"], 0)
        self.assertEqual(result["false_positives"], 0)
        self.assertEqual(result["latency_samples"], 60)
        self.assertEqual(set(result["matched_by_rule"]), {
            "access_outside_approval", "unexpected_role_change",
            "review_after_role_change", "lateral_movement_candidate",
        })
        self.assertGreaterEqual(result["median_ms"], 0)
        self.assertGreaterEqual(result["p95_ms"], result["median_ms"])
