from datetime import datetime, timedelta
from itertools import permutations
from pathlib import Path
import selectors
import signal
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from console_scenarios import time_machine
from detection_cli import synthetic
from kig_core.archive import ArchiveConflict, ArchiveUnavailable, canonical
from kig_core.detector import analyze
from kig_core.detector_archive import PRODUCER, evidence_archive, open_evidence_archive, replay, source_event


class DetectorArchiveTest(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(TemporaryDirectory()))
        self.archive, self.writer, self.investigator = evidence_archive(self.directory)
        self.events, self.approvals, self.expected = next(synthetic(1))

    def replay(self, events):
        return replay(self.archive, self.writer, self.investigator, events, self.approvals)

    def test_sources_precede_alerts_and_duplicates_are_idempotent(self):
        result = self.replay([*self.events, self.events[0]])
        self.assertEqual(len(result["sources"]), 10)
        self.assertEqual({(item["anchor_event_id"], item["event"]["rule_id"])
                          for item in result["findings"]}, self.expected)
        for item in result["findings"]:
            event, alert = item["event"], item["receipt"]
            self.assertEqual(alert["state"], "CONFIRMED")
            self.assertEqual(event["rule_version"], 1 if event["rule_id"] == "unexpected_allowed_access" else 2)
            for ref in event["source_ids"]:
                self.assertEqual(ref["producer"], PRODUCER)
                retained = self.archive.retrieve(self.investigator, **ref)
                self.assertEqual(retained["lifecycle"], "CONFIRMED")
                self.assertLess(retained["terminal_receipt"]["sequence"], alert["sequence"])
        self.assertEqual([item["receipt"] for item in result["findings"]],
                         [item["receipt"] for item in self.replay(self.events)["findings"]])

    def test_connected_path_every_arrival_order(self):
        hops = [event for event in self.events if "worker-hop" in event["event_id"]]
        third = dict(hops[0], event_id="third-hop", source_service="archive", target_service="billing-log")
        for observations in permutations([*hops, third]):
            with self.subTest(order=[item["event_id"] for item in observations]):
                alerts, _ = analyze(observations, self.approvals)
                self.assertEqual(len(alerts), 3)
                self.assertEqual({alert["anchor_event_id"] for alert in alerts},
                                 {event["event_id"] for event in observations})
        repeated = dict(hops[0], event_id="repeated-hop")
        result = self.replay([*hops, third, repeated, third])
        self.assertEqual(len(result["sources"]), 4)
        self.assertEqual(len(result["findings"]), 4)
        self.assertEqual({item["anchor_event_id"] for item in result["findings"]},
                         {event["event_id"] for event in [*hops, third, repeated]})
        self.assertTrue(all(item["receipt"]["state"] == "CONFIRMED" for item in result["findings"]))

    def test_connected_path_uses_inclusive_correlation_horizon(self):
        first, second = [event for event in self.events if "worker-hop" in event["event_id"]]
        start = datetime.fromisoformat(first["event_time_utc"])
        for seconds, expected in ((30, 2), (30.001, 0), (86400, 0)):
            with self.subTest(seconds=seconds):
                stamp = (start + timedelta(seconds=seconds)).isoformat()
                later = dict(second, event_time_utc=stamp, received_time_utc=stamp)
                self.assertEqual(len(analyze([first, later], self.approvals)[0]), expected)

    def test_conflicts_and_missing_source_fail_closed(self):
        report = self.replay(self.events)
        conflicting = dict(self.events[0], outcome="deny")
        with self.assertRaises(ArchiveConflict):
            self.replay([conflicting])
        with self.assertRaises(ArchiveConflict):
            self.replay([self.events[0], conflicting])
        event = dict(report["findings"][0]["event"], event_id="unbound-alert",
                     source_ids=[{"producer": "other-producer", "event_id": self.events[0]["event_id"]}])
        with self.assertRaises(ArchiveConflict):
            self.archive.record_telemetry(self.writer, canonical(event))
        with self.assertRaises(LookupError):
            self.archive.retrieve(self.investigator, PRODUCER, "unbound-alert")
        self.archive.path.unlink()
        with self.assertRaises(ArchiveUnavailable):
            self.replay(self.events)

    def test_process_kill_during_archive_transaction_preserves_only_committed_sources(self):
        for event in self.events:
            self.archive.record_telemetry(self.writer, canonical(source_event(event)))
        command = """
import signal, sys
from datetime import datetime, timedelta
from itertools import permutations
from pathlib import Path
from detection_cli import synthetic
from kig_core.detector import analyze
from kig_core.detector_archive import open_evidence_archive, replay

def stop(*args):
    print("OPEN", flush=True)
    while True:
        signal.pause()

archive, writer, investigator = open_evidence_archive(Path(sys.argv[1]))
archive._terminal = stop
events, approvals, _ = next(synthetic(1))
replay(archive, writer, investigator, events, approvals)
"""
        with subprocess.Popen([sys.executable, "-c", command, str(self.directory)],
                              stdout=subprocess.PIPE, text=True) as child:
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stdout, selectors.EVENT_READ)
                    self.assertTrue(selector.select(timeout=8))
                self.assertEqual(child.stdout.readline().strip(), "OPEN")
            finally:
                if child.poll() is None:
                    child.kill()
                self.assertEqual(child.wait(timeout=5), -signal.SIGKILL)
        reopened, writer, investigator = open_evidence_archive(self.directory)
        position = reopened.position(writer)
        self.assertFalse(position["has_pending"])
        self.assertEqual(position["sequence"], len(self.events) * 2)
        self.assertEqual(len(replay(reopened, writer, investigator, self.events, self.approvals)["findings"]), 5)

    def test_out_of_order_clock_ambiguity_is_not_a_causal_alert(self):
        change = next(event for event in self.events if event["event_id"].endswith("unexpected-grant"))
        read = next(event for event in self.events if event["event_id"].endswith("follow-up"))
        read = dict(read, event_time_utc="2026-01-15T09:00:02.100Z", target_service="catalog")
        report = self.replay([read, change])
        self.assertIn({"event": read["event_id"], "reason": "order_uncertain"}, report["timing_notes"])
        self.assertEqual([item["event"]["rule_id"] for item in report["findings"]], ["unexpected_role_change"])
        self.assertEqual(report["sources"][0]["timing"]["uncertainty_ms"], 125)


class ArchiveScenarioTest(unittest.TestCase):
    def test_disposable_restore_preserves_quarantine_evidence_and_revocation(self):
        result = time_machine()
        self.assertEqual(result["historical"]["lifecycle"], "CONFIRMED")
        self.assertEqual(result["historical"]["producer"], "worker-B")
        for node in ("A", "B"):
            self.assertEqual(result["quarantine"][node]["status"], 503)
            self.assertEqual(result["recovered"][node]["teammate"]["status"], 200)
            self.assertEqual(result["recovered"][node]["revoked"]["reason"], "revoked_device")
