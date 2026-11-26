"""Post-quantum audit evidence for the local demo boundary."""
import base64
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PublicKey


ALGORITHM = "ML-DSA-65"
CONTEXT = b"devforge/track4/audit-evidence/v1"


def payload(challenge, event):
    return json.dumps({"challenge": challenge, "event": event}, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def attest(private_key, challenge, event):
    signature = private_key.sign(payload(challenge, event), context=CONTEXT)
    return {"algorithm": ALGORITHM, "challenge": challenge, "event": event,
            "signature": base64.b64encode(signature).decode("ascii")}


def verify_attestation(attestation, trusted_key, *, challenge, request_id):
    """The key, challenge and request ID come from the verifier."""
    try:
        event = attestation["event"]
        if (attestation["algorithm"] != ALGORITHM
                or attestation["challenge"] != challenge
                or event["request_id"] != request_id):
            return False
        key = MLDSA65PublicKey.from_public_bytes(trusted_key)
        signature = base64.b64decode(attestation["signature"], validate=True)
        key.verify(signature, payload(challenge, event), context=CONTEXT)
    except (InvalidSignature, KeyError, TypeError, ValueError):
        return False
    return True
