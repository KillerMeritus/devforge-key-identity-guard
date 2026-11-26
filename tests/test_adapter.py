import base64
import hmac
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from pqcrypto.kem import ml_kem_768


ENTRY = Path(__file__).resolve().parents[1] / "track4_service.py"


class AdapterTest(unittest.TestCase):
    def test_independent_proof_and_denial(self):
        with tempfile.TemporaryDirectory() as state:
            def call(op, **fields):
                result = subprocess.run(
                    [sys.executable, str(ENTRY)], input=json.dumps(dict(op=op, **fields)),
                    text=True, capture_output=True, check=True, timeout=8,
                    env={**os.environ, "TRACK4_STATE_DIR": state},
                )
                self.assertEqual(result.stderr, "")
                return json.loads(result.stdout)

            body, challenge = "पहली लाइन\nsecond line", "challenge🚀"
            self.assertEqual(call("setup", owners={"file": "owner"}, contents={"file": body},
                                  disabled=[], key_material="synthetic"), {"ready": True})
            public, private = ml_kem_768.generate_keypair()
            params = dict(actor="owner", asset="file", challenge=challenge,
                          public_key=base64.b64encode(public).decode())
            proof = call("protected_read", **params)
            secret = ml_kem_768.decrypt(private, base64.b64decode(proof["ciphertext"]))
            self.assertEqual(proof["proof"], hmac.digest(
                secret, (challenge + body).encode(), "sha256").hex())
            self.assertEqual(call("protected_read", **{**params, "public_key": "***"}),
                             {"decision": "deny"})
            call("revoke", actor="owner")
            self.assertEqual(call("protected_read", **params), {"decision": "deny"})
