"""Black-box checks of the organizer protocol through the root executable."""
import base64
import hmac
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey


ENTRY = Path(__file__).resolve().parents[1] / "track4_service.py"
DENY = {"decision": "deny"}


class RootAdapterContract(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.state = self.root / "state"

    def exchange(self, raw, state=None):
        result = subprocess.run(
            [sys.executable, str(ENTRY)], input=raw, cwd=self.root,
            text=True, encoding="utf-8", capture_output=True, timeout=8,
            env={**os.environ, "TRACK4_STATE_DIR": str(state or self.state),
                 "PYTHONDONTWRITEBYTECODE": "1"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(len(result.stdout.splitlines()), 1)
        return json.loads(result.stdout)

    def call(self, op, *, state=None, **data):
        return self.exchange(json.dumps({"op": op, **data}, ensure_ascii=False), state)

    def setup_fixture(self, owners, contents, disabled=(), *, state=None):
        self.assertEqual(self.call("setup", state=state, owners=owners, contents=contents,
                                  disabled=list(disabled), key_material="fixture-secret-omit"), {"ready": True})

    def read(self, actor, asset, request_id, *, state=None):
        return self.call("read", state=state, actor=actor, asset=asset, request_id=request_id)

    def test_root_subprocess_protocol(self):
        self.setup_fixture({"brief": "maya"}, {"brief": "value"})
        self.assertEqual(self.call("unsupported"), {"error": "unsupported_operation"})
        self.assertTrue((self.state / "judge.sqlite").is_file())

    def test_multiple_actors_and_assets(self):
        self.setup_fixture({"one": "maya", "two": "leo", "three": "maya"},
                           {"one": "1", "two": "2", "three": "3"})
        cases = (("maya", "one", "1"), ("leo", "two", "2"), ("maya", "three", "3"),
                 ("leo", "one", None), ("maya", "two", None), ("maya", "absent", None))
        for i, (actor, asset, value) in enumerate(cases):
            with self.subTest(actor=actor, asset=asset):
                expected = DENY if value is None else {"decision": "allow", "body": value}
                self.assertEqual(self.read(actor, asset, str(i)), expected)

    def test_initially_disabled_identity(self):
        self.setup_fixture({"a": "maya", "b": "leo"}, {"a": "1", "b": "2"}, disabled=("maya",))
        self.assertEqual(self.read("maya", "a", "a"), DENY)
        self.assertEqual(self.read("leo", "b", "b"), {"decision": "allow", "body": "2"})

    def test_repeated_revocation(self):
        self.setup_fixture({"a": "maya", "b": "leo"}, {"a": "1", "b": "2"})
        for i in range(3):
            self.assertEqual(self.call("revoke", actor="maya"), {})
            self.assertEqual(self.read("maya", "a", f"owner-{i}"), DENY)
        self.assertEqual(self.read("leo", "b", "peer"), {"decision": "allow", "body": "2"})

    def test_persistence_across_fresh_processes(self):
        self.setup_fixture({"a": "maya"}, {"a": "stored"})
        self.assertEqual(self.read("maya", "a", "pre"), {"decision": "allow", "body": "stored"})
        self.assertEqual(self.call("revoke", actor="maya"), {})
        self.assertEqual(self.read("maya", "a", "post"), DENY)
        self.assertEqual(self.call("audit", request_id="pre"), {"request_id": "pre", "decision": "allow"})
        self.assertEqual(self.call("audit", request_id="post"), {"request_id": "post", "decision": "deny"})
        self.assertEqual(self.call("setup", owners={"a": "maya"}, contents={"a": "replacement"}, disabled=[]),
                         {"error": "already_initialized"})

    def test_state_directory_isolation(self):
        other = self.root / "independent"
        self.setup_fixture({"a": "maya"}, {"a": "first"})
        self.setup_fixture({"a": "maya"}, {"a": "second"}, state=other)
        self.assertEqual(self.read("maya", "a", "same"), {"decision": "allow", "body": "first"})
        self.assertEqual(self.call("audit", request_id="same", state=other), {"error": "unknown_request"})
        self.call("revoke", actor="maya")
        self.assertEqual(self.read("maya", "a", "new"), DENY)
        self.assertEqual(self.read("maya", "a", "new", state=other), {"decision": "allow", "body": "second"})

    def test_empty_and_unicode_content(self):
        contents = {"blank": "", "पत्र": "पहली पंक्ति\n第二行 🗝️"}
        self.setup_fixture(dict.fromkeys(contents, "माया"), contents)
        for asset, body in contents.items():
            self.assertEqual(self.read("माया", asset, asset), {"decision": "allow", "body": body})

    def test_malformed_requests(self):
        self.setup_fixture({"a": "maya"}, {"a": "1"})
        for raw in ("", "{", "null", "[]", '{"op":1}', '{"op":"read","actor":[]}',
                    '{"op":"revoke","actor":null}', '{"op":"audit","request_id":42}',
                    '{"op":"setup","owners":{},"contents":{"a":"x"},"disabled":[]}'):
            with self.subTest(raw=raw):
                self.assertEqual(self.exchange(raw), {"error": "invalid_request"})

    def test_cross_implementation_ml_kem_proof(self):
        body, challenge = "समुद्र\n🌊", "épreuve 🔐"
        self.setup_fixture({"a": "maya"}, {"a": body})
        private = MLKEM768PrivateKey.generate()
        public = base64.b64encode(private.public_key().public_bytes_raw()).decode("ascii")
        result = self.call("protected_read", actor="maya", asset="a", challenge=challenge, public_key=public)
        self.assertEqual(set(result), {"ciphertext", "proof"})
        ciphertext = base64.b64decode(result["ciphertext"], validate=True)
        secret = private.decapsulate(ciphertext)
        self.assertEqual(result["proof"], hmac.digest(secret, (challenge + body).encode(), "sha256").hex())
        self.assertNotEqual(result["proof"], hmac.digest(secret, ("wrong" + body).encode(), "sha256").hex())

    def test_malformed_cryptographic_inputs(self):
        self.setup_fixture({"a": "maya"}, {"a": "1"})
        for public_key in ("***", "", "AA==", {}, 12, None):
            with self.subTest(public_key=public_key):
                self.assertEqual(self.call("protected_read", actor="maya", asset="a", challenge="x",
                                           public_key=public_key), DENY)
        private = MLKEM768PrivateKey.generate()
        public = base64.b64encode(private.public_key().public_bytes_raw()).decode("ascii")
        self.assertEqual(self.call("protected_read", actor="maya", asset="a", public_key=public), DENY)
        self.assertEqual(self.call("protected_read", actor="maya", asset="a", challenge=[], public_key=public), DENY)

    def test_unauthorized_protected_reads(self):
        self.setup_fixture({"a": "maya", "b": "leo"}, {"a": "1", "b": "2"}, disabled=("leo",))
        private = MLKEM768PrivateKey.generate()
        public = base64.b64encode(private.public_key().public_bytes_raw()).decode("ascii")
        for actor, asset in (("other", "a"), ("leo", "b"), ("maya", "missing")):
            with self.subTest(actor=actor, asset=asset):
                self.assertEqual(self.call("protected_read", actor=actor, asset=asset, challenge="x",
                                           public_key=public), DENY)
        self.call("revoke", actor="maya")
        self.assertEqual(self.call("protected_read", actor="maya", asset="a", challenge="x",
                                   public_key=public), DENY)

    def test_audit_correlates_and_preserves_original_decision(self):
        self.setup_fixture({"a": "maya", "b": "maya"}, {"a": "1", "b": "2"})
        self.assertEqual(self.read("maya", "a", "allow")["decision"], "allow")
        self.assertEqual(self.read("leo", "a", "deny"), DENY)
        self.assertEqual(self.read("maya", "b", "allow"), DENY)
        self.assertEqual(self.read("maya", "a", "deny"), DENY)
        for request_id in ("allow", "deny"):
            self.assertEqual(self.call("audit", request_id=request_id),
                             {"request_id": request_id, "decision": request_id})
        self.assertEqual(self.call("audit", request_id="absent"), {"error": "unknown_request"})

    def test_seeded_operation_sequences_against_reference_model(self):
        owners, contents = {"a": "maya", "b": "leo", "c": "ravi"}, {"a": "", "b": "β", "c": "3"}
        for seed in (4127, 5905):
            with self.subTest(seed=seed):
                rng = random.Random(seed)
                state = self.root / str(seed)
                disabled, ledger = {"ravi"}, {}
                self.setup_fixture(owners, contents, disabled, state=state)
                for index in range(48):
                    operation = rng.choices(("read", "revoke", "audit"), weights=(6, 1, 3))[0]
                    actor = rng.choice(("maya", "leo", "ravi", "unknown"))
                    asset = rng.choice(("a", "b", "c", "absent"))
                    request = f"request-{rng.randrange(15)}"
                    with self.subTest(index=index, operation=operation):
                        if operation == "revoke":
                            disabled.add(actor)
                            self.assertEqual(self.call(operation, actor=actor, state=state), {})
                        elif operation == "audit":
                            record = ledger.get(request)
                            expected = ({"request_id": request, "decision": record[2]} if record
                                        else {"error": "unknown_request"})
                            self.assertEqual(self.call(operation, request_id=request, state=state), expected)
                        else:
                            permitted = owners.get(asset) == actor and actor not in disabled
                            original = ledger.setdefault(request, (actor, asset, "allow" if permitted else "deny"))
                            expected = ({"decision": "allow", "body": contents[asset]}
                                        if permitted and original == (actor, asset, "allow") else DENY)
                            self.assertEqual(self.read(actor, asset, request, state=state), expected)
