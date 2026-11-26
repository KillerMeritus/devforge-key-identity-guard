import unittest

from detection_cli import benchmark
from kig_core.detector import analyze


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
