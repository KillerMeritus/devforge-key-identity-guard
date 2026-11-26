"""Loopback-only demo worker. Provision state with demo_cli."""
import argparse
from pathlib import Path
import sqlite3
import sys
import time

from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, StrictInt
import uvicorn

from kig_core.attestation import attest
from kig_core.detector import LATENESS_SECONDS
from kig_core.guard import Guard


class Request(BaseModel):
    target: str
    version: StrictInt | None = None
    approval: str | None = None
    public_key: str | None = None
    challenge: str | None = None


class AttestationRequest(BaseModel):
    challenge: str = Field(pattern=r"^[a-f0-9]{64}$", min_length=64, max_length=64)


def worker(state, node, stop_at=None):
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
            print(f"CHECKPOINT {phase}", flush=True)
            while True:
                time.sleep(60)

    keys = [(state / f"{name}.key").read_bytes() for name in ("audit", "storage", "backup")]
    guard = Guard(state / "demo.sqlite", *keys, checkpoint=checkpoint)
    api = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    def token(header):
        scheme, _, value = (header or "").partition(" ")
        return value if scheme.lower() == "bearer" else ""

    @api.exception_handler(sqlite3.Error)
    def database_error(_, __):
        return JSONResponse({"error": "state_unavailable"}, status_code=503)

    @api.exception_handler(ValueError)
    def evidence_error(_, __):
        return JSONResponse({"error": "verification_failed"}, status_code=503)

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
        event = find_evidence(request_id, authorization)
        if isinstance(event, JSONResponse):
            return event
        return {**event, "proof": "audit_chain_verified"}

    @api.post("/evidence/{request_id}/attestation")
    def attestation(request_id: str, request: AttestationRequest,
                    authorization: str | None = Header(default=None)):
        event = find_evidence(request_id, authorization)
        if isinstance(event, JSONResponse):
            return event
        if event["node"] != node:
            return JSONResponse({"error": "evidence_belongs_to_another_node"}, status_code=409)
        try:
            seed = (state / f"attestation-{node}.key").read_bytes()
            key = MLDSA65PrivateKey.from_seed_bytes(seed)
        except (OSError, ValueError):
            return JSONResponse({"error": "attestation_unavailable"}, status_code=503)
        return attest(key, node, request.challenge, event)

    @api.post("/message")
    def message(authorization: str | None = Header(default=None)):
        result = guard.execute(node, token(authorization), "message", "")
        if result["reason"] == "invalid_device":
            return JSONResponse({"error": "unauthenticated"}, status_code=401)
        if result["reason"] == "revoked_device":
            return JSONResponse({"error": "forbidden"}, status_code=403)
        return JSONResponse({"error": "messaging not supported in this track"},
                            status_code=501, headers={"X-Request-ID": result["request_id"]})

    @api.post("/{action}")
    def execute(action: str, request: Request, authorization: str | None = Header(default=None)):
        if action not in {"read", "revoke", "rotate", "enroll"}:
            return JSONResponse({"error": "unsupported_route"}, status_code=404)
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
    parser.add_argument("--test-stop-at", choices=["pre", "post"])
    args = parser.parse_args()
    uvicorn.run(worker(args.state, args.node, args.test_stop_at), host="127.0.0.1",
                port=args.port, access_log=False, log_level="warning")
