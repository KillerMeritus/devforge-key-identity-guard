"""R-21 boundary tests. No worker or cryptography dependencies."""
import unittest
from unittest.mock import Mock, patch

from kig_core.audit_observer import AuditObserver, MAX_POLLS


def denial(request_id):
    return {
        "node": "A", "request_id": request_id, "status": 403, "reason": "revoked_device",
        "body_withheld": True,
    }


def audit_event(request_id):
    return {
        "node": "A", "request_id": request_id, "id": 1, "actor": "owner",
        "credential_ref": "opaque", "target": "brief", "version": 2,
        "action": "read", "decision": "deny", "reason": "revoked_device", "timestamp": 1,
    }


class PollBudgetTests(unittest.TestCase):
    def setUp(self):
        self.guard = Mock()
        self.guard.evidence.return_value = []
        self.published = []
        self.observer = AuditObserver(self.guard, "test-operator", self.published.append)
        self.sleep = self.enterContext(patch("kig_core.audit_observer.time.sleep"))

    def test_missing_required_observation_at_limit(self):
        self.observer.poll("waiting for denial", [denial("missing")])

        self.assertEqual(self.guard.evidence.call_count, MAX_POLLS)
        report = self.observer.result()
        self.assertEqual(report["findings"], [])
        self.assertEqual(len(report["poll_samples"]), MAX_POLLS)
        self.assertEqual(len(report["status_events"]), 1)
        notice = report["status_events"][0]
        self.assertEqual(notice["rule"], "poll_budget_exhausted")
        self.assertEqual(notice["missing_request_ids"], ["missing"])
        self.assertTrue(notice["poll_attempted"])
        self.assertEqual(self.published, [{"type": "monitor_status", **notice}])
        self.assertEqual(self.sleep.call_count, MAX_POLLS - 1)

    def test_new_event_after_success_on_last_poll(self):
        event = audit_event("on-time")
        self.guard.evidence.side_effect = [*([[]] * (MAX_POLLS - 1)), [event]]
        self.observer.poll("last permitted read", [denial("on-time")])
        self.assertEqual(self.observer.result()["status_events"], [])

        self.guard.evidence.side_effect = None
        self.guard.evidence.return_value = [event, {**audit_event("too-late"), "id": 2}]
        self.observer.poll("next stage", [denial("too-late")])

        self.assertEqual(self.guard.evidence.call_count, MAX_POLLS)
        report = self.observer.result()
        self.assertEqual([item["request_id"] for item in report["findings"]], ["on-time"])
        self.assertEqual(report["findings"][0]["containment"], "CONFIRMED_DENIAL_NO_BODY")
        self.assertEqual(len(report["status_events"]), 1)
        notice = report["status_events"][0]
        self.assertEqual(notice["rule"], "poll_budget_exhausted")
        self.assertEqual(notice["missing_request_ids"], ["too-late"])
        self.assertFalse(notice["poll_attempted"])
        self.assertEqual(notice["stage"], "next stage")
        self.assertEqual(self.published[-1], {"type": "monitor_status", **notice})

    def test_skipped_checkpoint_without_an_explicit_request(self):
        self.observer.poll("waiting", [denial("missing")])
        self.observer.poll("skipped snapshot")
        self.observer.poll("skipped snapshot")

        self.assertEqual(self.guard.evidence.call_count, MAX_POLLS)
        notices = self.observer.result()["status_events"]
        self.assertEqual(len(notices), 2)
        expired, skipped = notices
        self.assertTrue(expired["poll_attempted"])
        self.assertFalse(skipped["poll_attempted"])
        self.assertEqual(skipped["missing_request_ids"], [])
        self.assertEqual(len(self.published), 2)


if __name__ == "__main__":
    unittest.main()
