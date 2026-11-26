"""Organizer boundary. Actor IDs are supplied by the trusted judge worker."""
import base64
import hmac

from .db import enable_wal, transaction


DENY = {"decision": "deny"}


def lookup(db, actor, asset):
    row = db.execute("""
        SELECT body FROM assets WHERE id=? AND owner=? AND NOT EXISTS
        (SELECT 1 FROM revoked WHERE actor=?)
        """, (asset, actor, actor)).fetchone()
    return row[0] if row else None


def protected_read(body, challenge, public_key):
    if body is None:
        return DENY
    from pqcrypto.kem import ml_kem_768
    try:
        key = base64.b64decode(public_key, validate=True)
        if len(key) != ml_kem_768.PUBLIC_KEY_SIZE:
            return DENY
        ciphertext, secret = ml_kem_768.encrypt(key)
    except (TypeError, ValueError, RuntimeError):
        return DENY
    return {"ciphertext": base64.b64encode(ciphertext).decode(),
            "proof": hmac.digest(secret, (challenge + body).encode(), "sha256").hex()}


def strings(request, *names):
    values = tuple(request.get(name) for name in names)
    if any(not isinstance(value, str) for value in values):
        raise ValueError("invalid fields")
    return values


def setup(path, request):
    owners, contents, disabled = (request.get(key) for key in ("owners", "contents", "disabled"))
    if not isinstance(owners, dict) or not isinstance(contents, dict) or not isinstance(disabled, list):
        raise ValueError("invalid setup")
    if owners.keys() != contents.keys() or any(
        not isinstance(value, str) for value in (*owners.values(), *contents.values(), *disabled)
    ):
        raise ValueError("invalid setup")
    enable_wal(path)
    with transaction(path) as db:
        db.execute("CREATE TABLE IF NOT EXISTS assets(id TEXT PRIMARY KEY, owner TEXT, body TEXT)")
        db.execute("CREATE TABLE IF NOT EXISTS revoked(actor TEXT PRIMARY KEY)")
        db.execute("CREATE TABLE IF NOT EXISTS decisions(id TEXT PRIMARY KEY, decision TEXT)")
        if db.execute("SELECT 1 FROM sqlite_master WHERE name='initialized'").fetchone():
            return {"error": "already_initialized"}
        db.execute("CREATE TABLE initialized(marker INTEGER)")
        db.executemany("INSERT INTO assets VALUES (?,?,?)",
                       ((asset, actor, contents[asset]) for asset, actor in owners.items()))
        db.executemany("INSERT OR IGNORE INTO revoked VALUES (?)", ((actor,) for actor in disabled))
    return {"ready": True}


def dispatch(path, request):
    op, = strings(request, "op")
    if op == "setup":
        return setup(path, request)
    if op == "read":
        actor, asset, request_id = strings(request, "actor", "asset", "request_id")
        with transaction(path) as db:
            body = lookup(db, actor, asset)
            decision = "deny" if body is None else "allow"
            db.execute("INSERT INTO decisions VALUES (?,?) ON CONFLICT(id) DO UPDATE SET decision=excluded.decision", (request_id, decision))
        return DENY if body is None else {"decision": "allow", "body": body}
    if op == "revoke":
        actor, = strings(request, "actor")
        with transaction(path) as db:
            db.execute("INSERT OR IGNORE INTO revoked VALUES (?)", (actor,))
        return {}
    if op == "audit":
        request_id, = strings(request, "request_id")
        with transaction(path, write=False) as db:
            row = db.execute("SELECT decision FROM decisions WHERE id=?", (request_id,)).fetchone()
        return {"request_id": request_id, "decision": row[0]} if row else {"error": "unknown_request"}
    if op == "protected_read":
        actor, asset = strings(request, "actor", "asset")
        try:
            challenge, key = strings(request, "challenge", "public_key")
        except ValueError:
            return DENY
        with transaction(path, write=False) as db:
            body = lookup(db, actor, asset)
        return protected_read(body, challenge, key)
    return {"error": "unsupported_operation"}
