"""Loopback-only demo worker. Provision state with demo_cli."""
import argparse
import json
from pathlib import Path
import sqlite3
import sys
import time

from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
from cryptography.exceptions import InvalidTag
from fastapi import FastAPI, Header
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, StrictInt
import uvicorn

from kig_core.attestation import attest
from kig_core.archive import ArchiveConflict, ArchiveDenied, ArchiveUnavailable
from kig_core.detector import LATENESS_SECONDS
from kig_core.guard import Guard
from kig_core.witness import RevocationWitness
from kig_core.worker_archive import ArchivedGuard, MUTATIONS, PendingRecovery, RetryDenied, open_archive


class Request(BaseModel):
    target: str = Field(max_length=128)
    version: StrictInt | None = None
    approval: str | None = Field(default=None, max_length=128)
    public_key: str | None = Field(default=None, max_length=2048)
    challenge: str | None = Field(default=None, max_length=1024)


class AttestationRequest(BaseModel):
    challenge: str = Field(pattern=r"^[a-f0-9]{64}$", min_length=64, max_length=64)


def worker(state, node, stop_at=None, *, archive=False):
    def checkpoint(phase):
        if phase == "prepared" and stop_at:
            print("CHECKPOINT prepared", flush=True)
            release = state / "resume-rotation"
            deadline = time.monotonic() + 5
            while not release.exists():
                if time.monotonic() >= deadline:
                    raise RuntimeError("Rotation preparation checkpoint expired")
                time.sleep(0.01)
        if phase == stop_at:
            if phase == "post":
                print(f"COMMIT_OBSERVED_NS {time.monotonic_ns()}", flush=True)
            print(f"CHECKPOINT {phase}", flush=True)
            while True:
                time.sleep(60)

    keys = [(state / f"{name}.key").read_bytes() for name in ("audit", "storage", "backup")]
    witness = RevocationWitness(state / "witness" / "checkpoint.sqlite", keys[0])
    guard = Guard(state / "demo.sqlite", *keys, checkpoint=checkpoint, witness=witness,
                  bootstrap=False)
    guard.require_mode(archive=archive)
    api = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    def archived_guard():
        try:
            return ArchivedGuard(guard, state, node)
        except (OSError, ValueError) as error:
            raise ArchiveUnavailable("archive configuration unavailable") from error

    def token(header):
        scheme, _, value = (header or "").partition(" ")
        return value if scheme.lower() == "bearer" and len(value) <= 256 else ""

    @api.exception_handler(sqlite3.Error)
    def database_error(_, __):
        return JSONResponse({"error": "state_unavailable"}, status_code=503)

    @api.exception_handler(RequestValidationError)
    def invalid_request(_, __):
        return JSONResponse({"error": "invalid_request"}, status_code=422)

    @api.exception_handler(InvalidTag)
    @api.exception_handler(ValueError)
    def evidence_error(_, __):
        return JSONResponse({"error": "verification_failed"}, status_code=503)

    @api.exception_handler(PendingRecovery)
    def recovery_pending(_, __):
        return JSONResponse({"error": "recovery_pending"}, status_code=503)

    @api.exception_handler(ArchiveUnavailable)
    @api.exception_handler(OSError)
    def archive_error(_, __):
        return JSONResponse({"error": "audit_state_unavailable"}, status_code=503)

    @api.exception_handler(ArchiveDenied)
    def archive_producer_error(_, __):
        return JSONResponse({"error": "audit_state_unavailable"}, status_code=503)

    @api.exception_handler(ArchiveConflict)
    def archive_conflict(_, __):
        return JSONResponse({"error": "operation_conflict"}, status_code=409)

    @api.get("/health")
    def health():
        return {"node": node}

    @api.get("/config/clock-tolerance")
    def config():
        return {"tolerance_seconds": LATENESS_SECONDS}

    def find_evidence(request_id, authorization):
        try:
            events = guard.evidence(token(authorization))
        except PermissionError as error:
            return JSONResponse({"error": str(error)},
                                status_code=401 if str(error) == "unauthenticated" else 403)
        for event in events:
            if event.get("request_id") == request_id:
                return event
        return JSONResponse({"error": "unknown_request"}, status_code=404)

    @api.get("/evidence/{request_id}")
    def evidence(request_id: str, authorization: str | None = Header(default=None)):
        if archive:
            return archived_evidence(request_id, authorization,
                                     lambda event: {**event, "proof": "audit_chain_verified"})
        event = find_evidence(request_id, authorization)
        if isinstance(event, JSONResponse):
            return event
        return {**event, "proof": "audit_chain_verified"}

    @api.post("/evidence/{request_id}/attestation")
    def attestation(request_id: str, request: AttestationRequest,
                    authorization: str | None = Header(default=None)):
        def sign(event):
            if event["node"] != node:
                return JSONResponse({"error": "evidence_belongs_to_another_node"}, status_code=409)
            try:
                seed = (state / f"attestation-{node}.key").read_bytes()
                key = MLDSA65PrivateKey.from_seed_bytes(seed)
            except (OSError, ValueError):
                return JSONResponse({"error": "attestation_unavailable"}, status_code=503)
            return attest(key, node, request.challenge, event)

        if archive:
            return archived_evidence(request_id, authorization, sign)
        event = find_evidence(request_id, authorization)
        return event if isinstance(event, JSONResponse) else sign(event)

    def archived_evidence(request_id, authorization, render):
        result = archived_guard().execute(token(authorization), "evidence", request_id, render=render)
        if result["allowed"]:
            return result["evidence"]
        reason = result["reason"]
        status, error = {"invalid_device": (401, "unauthenticated"),
                         "unknown_request": (404, "unknown_request")}.get(reason, (403, "forbidden"))
        return JSONResponse({"error": error}, status_code=status)

    @api.get("/historical/{producer}/{event_id}")
    def historical(producer: str, event_id: str, authorization: str | None = Header(default=None)):
        if not archive:
            return JSONResponse({"error": "unsupported_route"}, status_code=404)
        try:
            retained = open_archive(state).retrieve(token(authorization), producer, event_id)
        except ArchiveDenied:
            return JSONResponse({"error": "forbidden"}, status_code=403)
        except LookupError:
            return JSONResponse({"error": "unknown_event"}, status_code=404)
        raw = retained.pop("event_bytes")
        return {**retained, "original_canonical_event": raw.decode("ascii"),
                "event": json.loads(raw)}

    @api.post("/message")
    def message(authorization: str | None = Header(default=None)):
        if archive:
            return JSONResponse({"error": "messaging not supported in this track"}, status_code=501)
        result = guard.execute(node, token(authorization), "message", "")
        if result["reason"] == "invalid_device":
            return JSONResponse({"error": "unauthenticated"}, status_code=401)
        if result["reason"] == "revoked_device":
            return JSONResponse({"error": "forbidden"}, status_code=403)
        return JSONResponse({"error": "messaging not supported in this track"},
                            status_code=501, headers={"X-Request-ID": result["request_id"]})

    @api.post("/{action}")
    def execute(action: str, request: Request, authorization: str | None = Header(default=None),
                idempotency_key: str | None = Header(default=None)):
        if action not in {"read", "revoke", "rotate", "enroll"}:
            return JSONResponse({"error": "unsupported_route"}, status_code=404)
        if archive:
            if idempotency_key and len(idempotency_key) > 128:
                return JSONResponse({"error": "invalid_request"}, status_code=422)
            if action in MUTATIONS and not idempotency_key:
                return JSONResponse({"error": "idempotency_key_required"}, status_code=400)
            try:
                result = archived_guard().execute(token(authorization), action, **request.model_dump(),
                                                  idempotency_key=idempotency_key)
            except RetryDenied:
                return JSONResponse({"error": "forbidden"}, status_code=403)
        else:
            result = guard.execute(node, token(authorization), action, **request.model_dump())
        status = 200 if result["allowed"] else 403
        if result["reason"] == "invalid_device":
            status = 401
        return JSONResponse(result, status_code=status)

    return api


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--node", required=True, choices=["A", "B"])
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--test-stop-at", choices=["pre", "committed", "post"])
    parser.add_argument("--archive", action="store_true")
    args = parser.parse_args()
    try:
        app = worker(args.state, args.node, args.test_stop_at, archive=args.archive)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Worker startup refused: {error}\n")
    uvicorn.run(app, host="127.0.0.1",
                port=args.port, access_log=False, log_level="warning")
