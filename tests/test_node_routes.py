from contextlib import ExitStack
from pathlib import Path
import secrets
import tempfile
import unittest

from demo_cli import call, start
from kig_core.detector import LATENESS_SECONDS
from kig_core.guard import Guard


class NodeRoutesTest(unittest.TestCase):
    def test_messaging_stub_and_config(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            state = Path(directory)
            keys = [secrets.token_bytes(32) for _ in range(3)]
            for name, key in zip(("audit", "storage", "backup"), keys):
                (state / f"{name}.key").write_bytes(key)
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
