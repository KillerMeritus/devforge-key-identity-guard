from contextlib import ExitStack
from pathlib import Path
import secrets
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey

from demo_cli import call, start
from kig_core.attestation import verify_attestation
from kig_core.detector import LATENESS_SECONDS
from kig_core.guard import Guard


class NodeRoutesTest(unittest.TestCase):
    def test_messaging_stub_and_config(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            state = Path(directory)
            keys = [secrets.token_bytes(32) for _ in range(3)]
            for name, key in zip(("audit", "storage", "backup"), keys):
                (state / f"{name}.key").write_bytes(key)
            seed = secrets.token_bytes(32)
            (state / "attestation-A.key").write_bytes(seed)
            public = MLDSA65PrivateKey.from_seed_bytes(seed).public_key().public_bytes_raw()
            guard = Guard(state / "demo.sqlite", *keys)
            admin = guard.enroll("operator", "admin")
            reader = guard.enroll("reader")
            port, _ = start(stack, state, "A", state / "worker.log")
            self.assertEqual(call(port, "message", fields={})[0], 401)
            status, response, headers = call(port, "message", reader, {})
            self.assertEqual(status, 501)
            self.assertEqual(response, {"error": "messaging not supported in this track"})
            route = f"evidence/{headers['X-Request-ID']}"
            self.assertEqual(call(port, route, reader)[0], 403)
            status, evidence, _ = call(port, route, admin)
            self.assertEqual(status, 200)
            self.assertEqual(evidence["reason"], "messaging_unsupported")
            self.assertEqual(evidence["proof"], "audit_chain_verified")
            self.assertEqual(call(port, "config/clock-tolerance")[1],
                             {"tolerance_seconds": LATENESS_SECONDS})
            challenge = secrets.token_hex(32)
            attestation_route = f"{route}/attestation"
            fields = {"challenge": challenge}
            self.assertEqual(call(port, attestation_route, fields=fields)[0], 401)
            self.assertEqual(call(port, attestation_route, reader, fields)[0], 403)
            self.assertEqual(call(port, attestation_route, admin, {"challenge": "short"})[0], 422)
            status, signed, _ = call(port, attestation_route, admin, fields)
            self.assertEqual(status, 200)

            def verify(envelope, *, key=public, nonce=challenge, request_id=headers["X-Request-ID"]):
                return verify_attestation(envelope, key, node="A", challenge=nonce, request_id=request_id)

            self.assertTrue(verify(signed))
            self.assertFalse(verify(signed, nonce=secrets.token_hex(32)))
            self.assertFalse(verify(signed, request_id="different-request"))
            another_key = MLDSA65PrivateKey.generate().public_key().public_bytes_raw()
            self.assertFalse(verify(signed, key=another_key))
            changed = {**signed, "event": {**signed["event"], "decision": "allow"}}
            self.assertFalse(verify(changed))
            second = MLDSA65PrivateKey.generate()
            (state / "attestation-B.key").write_bytes(second.private_bytes_raw())
            port_b, _ = start(stack, state, "B", state / "worker-b.log")
            self.assertEqual(call(port_b, attestation_route, admin, fields)[0], 409)
            self.assertFalse(verify({**signed, "node": "B"}))
            self.assertFalse(verify_attestation(
                signed, second.public_key().public_bytes_raw(), node="B",
                challenge=challenge, request_id=headers["X-Request-ID"],
            ))
            with guard.transaction() as db:
                db.execute("UPDATE audit SET event='{}' WHERE id=1")
            self.assertEqual(call(port, attestation_route, admin, fields)[0], 503)
            with guard.transaction() as db:
                db.execute("UPDATE devices SET revoked=1 WHERE token=?", (guard.digest(admin),))
            self.assertEqual(call(port, attestation_route, admin, fields)[0], 403)
