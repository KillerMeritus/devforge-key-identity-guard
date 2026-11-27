import unittest
from copy import deepcopy
from detection_cli import synthetic
from kig_core.detector import analyze


class CorrelationBoundary(unittest.TestCase):
    def test_remote_time_and_distinct_flow(self):
        events, approvals, _ = next(synthetic(1))
        change = next(e for e in events if e['event_id'].endswith('unexpected-grant'))
        read = next(e for e in events if e['event_id'].endswith('follow-up'))
        for patch in [dict(correlation_id='other'),
                      dict(event_time_utc='2026-01-16T09:00:00Z', received_time_utc='2026-01-16T09:00:00Z')]:
            with self.subTest(patch=patch):
                alerts, _ = analyze([change, dict(read, **patch)], approvals)
                self.assertNotIn('review_after_role_change', [a['rule'] for a in alerts])

    def test_empty_scope_and_uncertain_expiry(self):
        events, approvals, _ = next(synthetic(1))
        grant = next(e for e in events if e["event_id"].endswith("-grant") and e["approval_id"])
        expired = next(e for e in events if e["event_id"].endswith("expired-read"))
        for scope in ({}, {"scope": []}):
            approval = dict(approvals[0])
            del approval["scope"]
            alerts, _ = analyze([grant], [dict(approval, **scope)])
            self.assertEqual(alerts[0]["classification"], "policy_violation")
        alerts, _ = analyze([expired], approvals)
        self.assertEqual(alerts[0]["classification"], "investigate")
        alerts, _ = analyze([dict(expired, target_service="unrelated")], approvals)
        self.assertEqual(alerts[0]["classification"], "policy_violation")

    def test_disconnected_edges(self):
        events, approvals, _ = next(synthetic(1))
        first, second = [deepcopy(e) for e in events if 'worker-hop' in e['event_id']]
        second.update(source_service='unrelated', target_service='elsewhere')
        alerts, _ = analyze([first, second], approvals)
        self.assertEqual(alerts, [])


class PassportBoundary(unittest.TestCase):
    def test_offline_expectations_and_original_bytes(self):
        from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
        from kig_core.attestation import attest
        from evidence_passport import verify
        key = MLDSA65PrivateKey.generate()
        pub = key.public_key().public_bytes_raw()
        event = dict(node='A', request_id='r', version=1, allowed=False, reason='revoked_device')
        record = attest(key, 'A', 'ab'*32, event)
        args = [pub, 'A', 'ab'*32, 'r']
        self.assertTrue(verify(record, *args))
        for field in record:
            with self.subTest(missing=field):
                self.assertFalse(verify({k:v for k,v in record.items() if k != field}, *args))
        for patch in [dict(signed_bytes='AAAA'), dict(signature='AAAA'), dict(node='B'),
                      dict(event=dict(event, version=2))]:
            self.assertFalse(verify(dict(record, **patch), *args))
        for index, other in enumerate([MLDSA65PrivateKey.generate().public_key().public_bytes_raw(),
                                       'B', 'cd'*32, 'different']):
            wrong = args.copy()
            wrong[index] = other
            self.assertFalse(verify(record, *wrong))
