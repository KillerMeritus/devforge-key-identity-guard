"""Disposable local fixtures for the Recovery Console."""

from contextlib import ExitStack, closing
from pathlib import Path
import secrets
import sqlite3
import tempfile
import time

from demo_cli import call, require, start
from detection_cli import synthetic
from kig_core.detector_archive import evidence_archive, replay
from kig_core.guard import Guard
from kig_core.witness import RevocationWitness
from kig_core.worker_archive import ArchivedGuard, provision_archive


def detector_replay():
    events, approvals, _ = next(synthetic(1))
    read = next(event for event in events if event["event_id"].endswith("-follow-up"))
    events.append(dict(read, event_id="clock-overlap", target_service="catalog",
                       event_time_utc="2026-01-15T09:00:02.100Z"))
    events.sort(key=lambda event: event["received_time_utc"])
    with tempfile.TemporaryDirectory(prefix="track4-detector-") as directory:
        return replay(*evidence_archive(Path(directory)), events, approvals)


def copy_database(source, destination):
    with closing(sqlite3.connect(source)) as original, closing(sqlite3.connect(destination)) as copy:
        original.backup(copy)


def time_machine():
    with tempfile.TemporaryDirectory(prefix="track4-time-machine-") as directory:
        state = Path(directory)
        keys = [secrets.token_bytes(32) for _ in range(3)]
        for name, key in zip(("audit", "storage", "backup"), keys):
            (state / f"{name}.key").write_bytes(key)
        witness_path = state / "witness" / "checkpoint.sqlite"
        witness_path.parent.mkdir()
        witness = RevocationWitness(witness_path, keys[0])
        witness.provision()
        working = state / "demo.sqlite"
        guard = Guard(working, *keys, witness=witness)
        operator = guard.enroll("operator", "admin")
        owner, teammate = guard.enroll("owner"), guard.enroll("teammate")
        guard.seed_file("brief", b"archive demonstration", "owner", "teammate")
        grants = provision_archive(state, guard)
        stale, current = state / "stale.sqlite", state / "current.sqlite"
        fields = {"target": "brief", "version": 1}
        nodes = ("A", "B")

        def observe(port, token):
            status, result, _ = call(port, "read", token, fields)
            require(status == 200 or "body" not in result, "denial disclosed protected content")
            return dict(status=status, reason=result.get("reason", result.get("error")),
                        request_id=result.get("request_id"))

        def ports(stack, stage):
            return {node: start(stack, state, node, state / f"{stage}-{node}.log", archive=True)[0]
                    for node in nodes}

        with ExitStack() as stack:
            live = ports(stack, "live")
            status, revocation, _ = call(live["A"], "revoke", operator, {"target": guard.digest(owner)},
                                         idempotency_key="revoke-owner")
            require(status == 200, "revocation failed")
            copy_database(working, stale)
            later = observe(live["B"], owner)
            require(later["status"] == 403 and later["reason"] == "revoked_device", "revocation lost")
        copy_database(working, current)
        copy_database(stale, working)
        historical_route = "historical/worker-B/" + later["request_id"]

        with ExitStack() as stack:
            quarantine = ports(stack, "quarantine")
            blocked = {node: observe(port, teammate) for node, port in quarantine.items()}
            require(all(item["status"] == 503 for item in blocked.values()), "stale state served")
            require(call(quarantine["A"], historical_route, operator)[0] == 403,
                    "working-store identity obtained historical evidence")
            status, historical, _ = call(quarantine["A"], historical_route, grants["investigator"])
            require(status == 200 and historical["lifecycle"] == "CONFIRMED"
                    and historical["event"]["request_id"] == later["request_id"]
                    and historical["event"]["reason"] == later["reason"]
                    and historical["intent_receipt"]["producer"] == "worker-B",
                    "historical receipt did not match the retained observation")

            started = time.monotonic()
            ArchivedGuard(guard, state).restore_verified(current)
            recovered = {node: dict(teammate=observe(port, teammate), revoked=observe(port, owner))
                         for node, port in quarantine.items()}
            elapsed = round((time.monotonic() - started) * 1000, 2)
            require(all(item["teammate"]["status"] == 200 and item["revoked"]["status"] == 403
                        and item["revoked"]["reason"] == "revoked_device" for item in recovered.values()),
                    "verified restore did not preserve expected authorization")

        intent, terminal = historical["intent_receipt"], historical["terminal_receipt"]
        return {
            "revocation_request_id": revocation["request_id"], "quarantine": blocked,
            "historical": {"event": historical["event"], "producer": intent["producer"],
                           "lifecycle": historical["lifecycle"], "intent_tag": intent["tag"],
                           "terminal_tag": terminal["tag"], "sequence": terminal["sequence"]},
            "recovered": recovered, "recovery_ms": elapsed,
        }
