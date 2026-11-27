"""Post-quantum audit evidence for the local demo boundary."""
import base64
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PublicKey


ALGORITHM = "ML-DSA-65"
CONTEXT = b"devforge/track4/audit-evidence/v2"


def payload(node, challenge, event):
    return json.dumps({"node": node, "challenge": challenge, "event": event}, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def attest(private_key, node, challenge, event):
    signed_bytes = payload(node, challenge, event)
    signature = private_key.sign(signed_bytes, context=CONTEXT)
    return {"algorithm": ALGORITHM, "node": node, "challenge": challenge, "event": event,
            "signed_bytes": base64.b64encode(signed_bytes).decode("ascii"),
            "signature": base64.b64encode(signature).decode("ascii")}


def verify_attestation(attestation, trusted_key, *, node, challenge, request_id):
    """The verifier pins a key to its expected node."""
    try:
        event = attestation["event"]
        if (attestation["algorithm"] != ALGORITHM
                or attestation["node"] != node
                or event["node"] != node
                or attestation["challenge"] != challenge
                or event["request_id"] != request_id):
            return False
        key = MLDSA65PublicKey.from_public_bytes(trusted_key)
        signature = base64.b64decode(attestation["signature"], validate=True)
        key.verify(signature, payload(node, challenge, event), context=CONTEXT)
    except (InvalidSignature, KeyError, TypeError, ValueError):
        return False
    return True
