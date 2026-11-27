import io
import json
import secrets
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey

from console import Console
from kig_core.attestation import attest
from kig_core.audit_observer import AuditObserver
from kig_core.guard import Guard
from security_claims import appraise


class HistoricalClaimTests(unittest.TestCase):
    def setUp(self):
        self.keys = {node: MLDSA65PrivateKey.generate() for node in ("A", "B")}
        self.pins = {node: key.public_key().public_bytes_raw() for node, key in self.keys.items()}
        self.expected = {
            "actor": "owner", "asset": "brief", "version": 2,
            "nodes": {node: {"challenge": "ab" * 32, "request_id": f"req-{node}"} for node in self.keys},
        }

    def statement(self, node, **changes):
        expected = self.expected["nodes"][node]
        challenge = changes.pop("challenge", expected["challenge"])
        event = dict(node=node, request_id=expected["request_id"], actor="owner",
                     target="brief", version=2, action="read", decision="deny",
                     allowed=False, reason="revoked_device")
        return attest(self.keys[node], node, challenge, {**event, **changes})

    def test_all_three_claims(self):
        for claim, changes in (
            ("revoked-device", {}),
            ("teammate-read", dict(actor="teammate", allowed=True, decision="allow", reason="read")),
            ("retired-version", dict(version=1, reason="wrong_version")),
        ):
            expected = dict(self.expected, actor=changes.get("actor", "owner"),
                            version=changes.get("version", 2))
            statements = [self.statement(node, **changes) for node in self.keys]
            self.assertEqual(appraise(claim, statements, expected, self.pins), "VERIFIED")

    def test_incomplete_observations_or_expectations(self):
        a, b = [self.statement(node) for node in self.keys]
        for evidence, expectations, pins in (
            ([a], self.expected, self.pins),
            ([a, b], self.expected, {"A": self.pins["A"]}),
            ([a, b], dict(self.expected, nodes={"A": self.expected["nodes"]["A"]}), self.pins),
            ([a, b], {key: value for key, value in self.expected.items() if key != "actor"}, self.pins),
            ([a, b], {key: value for key, value in self.expected.items() if key != "version"}, self.pins),
        ):
            self.assertEqual(appraise("revoked-device", evidence, expectations, pins),
                             "INSUFFICIENT EVIDENCE")

    def test_authentic_but_conflicting_or_substituted_evidence(self):
        a = self.statement("A")
        for change in (
            {"allowed": True, "decision": "allow"}, {"reason": "wrong_version"},
            {"actor": "someone-else"}, {"target": "other"}, {"version": 1}, {"action": "rotate"},
            {"request_id": "another-request"}, {"challenge": "cd" * 32},
        ):
            with self.subTest(change=change):
                self.assertEqual(appraise("revoked-device", [a, self.statement("B", **change)],
                                          self.expected, self.pins), "FAILED")
        for statements, pins in (
            ([a, a], self.pins),
            ([a, {**a, "node": "B"}], self.pins),
            ([a, self.statement("B")], dict(self.pins, B=self.pins["A"])),
            ([a, self.statement("B")], dict(self.pins, B=MLDSA65PrivateKey.generate().public_key().public_bytes_raw())),
        ):
            self.assertEqual(appraise("revoked-device", statements, self.expected, pins), "FAILED")


class AuditObserverTests(unittest.TestCase):
    def test_authority_integrity_identity_and_containment(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        database = root / "demo.sqlite"
        guard = Guard(database, secrets.token_bytes(32), secrets.token_bytes(32))
        operator, reader = guard.enroll("operator", "admin"), guard.enroll("teammate")
        guard.seed_file("brief", b"synthetic", "teammate")
        unauthorized = AuditObserver(guard, reader, lambda _: None)
        unauthorized.poll("restricted")
        self.assertEqual(unauthorized.result()["status_events"][0]["rule"], "evidence_unavailable")
        published = []
        observer = AuditObserver(guard, operator, published.append)
        observer.poll("before write")
        result = guard.execute("A", reader, "read", "brief", version=2)
        self.assertEqual(result["reason"], "wrong_version")
        observed = dict(request_id=result["request_id"], node="A", status=403,
                        body_withheld=True, reason="wrong_version")
        observer.poll("wrong worker", [dict(observed, node="B")])
        self.assertEqual(observer.result()["findings"][0]["containment"], "UNCONFIRMED")
        observer.poll("matching response", [observed])
        observer.poll("repeat")
        self.assertEqual([item["type"] for item in published], ["finding", "containment"])
        self.assertEqual(observer.result()["findings"][0]["containment"], "CONFIRMED_DENIAL_NO_BODY")

        with sqlite3.connect(database) as db:
            db.execute("UPDATE audit SET tag = 'changed' WHERE id=1")
        observer.poll("integrity")
        report = observer.result()
        self.assertEqual(report["status_events"][0]["rule"], "audit_integrity_failure")
        self.assertEqual(len(report["findings"]), 1)
        self.assertFalse(report["poll_samples"][-1]["verified"])

    def test_live_monitor_reports_unavailable_when_checkpoints_are_skipped(self):
        handler = Console.__new__(Console)
        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()
        handler.wfile = io.BytesIO()
        with patch("kig_core.audit_observer.MAX_POLLS", 1):
            handler.stream_monitor()

        records = [json.loads(line) for line in handler.wfile.getvalue().splitlines()]
        gaps = [item for item in records if item.get("rule") == "poll_budget_exhausted"]
        self.assertTrue(gaps)
        self.assertEqual({item["fixture"] for item in gaps}, {"approval", "recovery"})
        self.assertTrue(all(item["type"] == "monitor_status" and not item["poll_attempted"] for item in gaps))
        self.assertTrue(any(item["missing_request_ids"] for item in gaps))
        complete = records[-1]
        self.assertEqual((complete["type"], complete["status"]), ("complete", "UNAVAILABLE"))
        self.assertTrue(all(len(report["poll_samples"]) == 1 for report in complete["report"].values()))
