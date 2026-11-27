"""Appraise historical worker statements against independently provisioned policy."""
import argparse
import json
from pathlib import Path
import re

from evidence_passport import verify

CLAIMS = {
    "revoked-device": (False, "revoked_device"),
    "teammate-read": (True, "read"),
    "retired-version": (False, "wrong_version"),
}
NODES = {"A", "B"}


def appraise(claim, statements, expected, trusted_keys):
    """Expect asset, version, identity and externally observed per-node request bindings."""
    if claim not in CLAIMS or not isinstance(statements, list):
        return "FAILED"
    by_node = {}
    for statement in statements:
        node = statement.get("node") if isinstance(statement, dict) else None
        if not isinstance(node, str) or node not in NODES or node in by_node:
            return "FAILED"
        by_node[node] = statement
    if not isinstance(expected, dict) or not isinstance(trusted_keys, dict):
        return "INSUFFICIENT EVIDENCE"
    bindings = expected.get("nodes")
    identity = {name: expected[name] for name in ("actor", "credential_ref") if name in expected}
    asset, version = expected.get("asset"), expected.get("version")
    if not isinstance(bindings, dict) or not asset or version is None or not identity:
        return "INSUFFICIENT EVIDENCE"
    if (not isinstance(asset, str) or type(version) is not int or version < 1
            or any(not isinstance(value, str) or not value for value in identity.values())
            or set(bindings) - NODES or set(trusted_keys) - NODES):
        return "FAILED"
    missing = set(by_node) != NODES
    request_ids, pins = set(), set()
    allowed, reason = CLAIMS[claim]
    decision = "allow" if allowed else "deny"
    for node in sorted(NODES):
        binding, key = bindings.get(node), trusted_keys.get(node)
        if not isinstance(binding, dict) or not key:
            missing = True
            continue
        challenge, request_id = binding.get("challenge"), binding.get("request_id")
        if not challenge or not request_id:
            missing = True
            continue
        if (not isinstance(key, bytes) or key in pins
                or not isinstance(challenge, str) or not re.fullmatch(r"[a-f0-9]{64}", challenge)
                or not isinstance(request_id, str) or request_id in request_ids):
            return "FAILED"
        pins.add(key)
        request_ids.add(request_id)
        statement = by_node.get(node)
        if statement is None:
            continue
        if not verify(statement, key, node, challenge, request_id):
            return "FAILED"
        event = statement["event"]
        required = dict(identity, target=asset, action="read", allowed=allowed,
                        decision=decision, reason=reason, version=version)
        if any(event.get(name) != value for name, value in required.items()):
            return "FAILED"
    return "INSUFFICIENT EVIDENCE" if missing else "VERIFIED"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("claim", choices=CLAIMS)
    parser.add_argument("--expected", type=Path, required=True)
    parser.add_argument("--key-a", type=Path)
    parser.add_argument("--key-b", type=Path)
    parser.add_argument("statements", nargs="*", type=Path)
    args = parser.parse_args()
    try:
        keys = {node: path.read_bytes() for node, path in (("A", args.key_a), ("B", args.key_b)) if path}
        status = appraise(args.claim, [json.loads(path.read_bytes()) for path in args.statements],
                          json.loads(args.expected.read_bytes()), keys)
    except FileNotFoundError:
        status = "INSUFFICIENT EVIDENCE"
    except (OSError, ValueError):
        status = "FAILED"
    print(status)
    return {"VERIFIED": 0, "FAILED": 1, "INSUFFICIENT EVIDENCE": 2}[status]


if __name__ == "__main__":
    raise SystemExit(main())
