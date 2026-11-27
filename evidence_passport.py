"""Verify an original worker statement offline with externally pinned expectations."""
import argparse
import base64
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PublicKey
from kig_core.attestation import ALGORITHM, CONTEXT


def verify(envelope, key, node, challenge, request_id):
    try:
        raw = base64.b64decode(envelope['signed_bytes'], validate=True)
        signature = base64.b64decode(envelope['signature'], validate=True)
        MLDSA65PublicKey.from_public_bytes(key).verify(signature, raw, context=CONTEXT)
        signed = json.loads(raw)
        event = signed['event']
        if (envelope['algorithm'] != ALGORITHM or signed['node'] != node
                or signed['challenge'] != challenge or event['node'] != node
                or event['request_id'] != request_id or json.dumps(envelope['event'], sort_keys=True) != json.dumps(event, sort_keys=True)
                or envelope['node'] != node or envelope['challenge'] != challenge
                or type(event['version']) is not int or type(event['allowed']) is not bool
                or not event['reason']):
            return False
    except (InvalidSignature, KeyError, TypeError, ValueError):
        return False
    return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('statement', type=Path)
    parser.add_argument('--key', required=True, type=Path)
    for name in ('node', 'challenge', 'request-id'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    try:
        valid = verify(json.loads(args.statement.read_bytes()), args.key.read_bytes(),
                       args.node, args.challenge, args.request_id)
    except (OSError, ValueError):
        valid = False
    print('VERIFIED' if valid else 'REJECTED')
    raise SystemExit(0 if valid else 1)
