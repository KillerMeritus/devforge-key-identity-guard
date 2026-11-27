"""Disposable local fixtures for the Recovery Console."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, closing
from pathlib import Path
import secrets
import base64
import sqlite3
import tempfile
import time

from demo_cli import call, require, run, start
from detection_cli import synthetic
from kig_core.detector_archive import evidence_archive, replay
from kig_core.audit_observer import AuditObserver
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



def approval_lab(competing, publish_audit=None):
    with tempfile.TemporaryDirectory(prefix="track4-approval-") as directory, ExitStack() as stack:
        state = Path(directory)
        keys = [secrets.token_bytes(32) for _ in range(3)]
        for name, key in zip(("audit", "storage", "backup"), keys):
            (state / f"{name}.key").write_bytes(key)
        witness_path = state / "witness" / "checkpoint.sqlite"
        witness_path.parent.mkdir()
        witness = RevocationWitness(witness_path, keys[0])
        witness.provision()
        guard = Guard(state / "demo.sqlite", *keys, witness=witness)
        admin, reader = guard.enroll("operator", "admin"), guard.enroll("teammate")
        observer = AuditObserver(guard, admin, publish_audit) if publish_audit else None
        content = b"synthetic approval lab"
        guard.seed_file("brief", content, "teammate")
        ports = {node: start(stack, state, node, state / f"{node}.log")[0] for node in ("A", "B")}
        approval = guard.approve_rotation("operator", "brief", 1, time.time() + 120)

        def observe(node, action, token, fields):
            status, response, _ = call(ports[node], action, token, fields)
            body_withheld = {"body", "ciphertext", "proof", "token"}.isdisjoint(response)
            require(status == 200 or body_withheld, "denial disclosed protected content")
            if action == "read" and status == 200:
                require(base64.b64decode(response.get("body", ""), validate=True) == content,
                        "worker returned incorrect asset contents")
            return dict(node=node, status=status, reason=response.get("reason"),
                        request_id=response.get("request_id"),
                        body_withheld=body_withheld)

        def read(node, version):
            result = observe(node, "read", reader, {"target": "brief", "version": version})
            return dict(result, requested_version=version)

        def rotate(node, given_approval):
            return observe(node, "rotate", admin,
                           {"target": "brief", "version": 1, "approval": given_approval})

        before = [read(node, 1) for node in ports]
        require(all(item["status"] == 200 for item in before), "v1 unavailable before rotation")
        if competing:
            other = guard.approve_rotation("operator", "brief", 1, time.time() + 120)
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(rotate, node, grant) for node, grant in zip(ports, (approval, other))]
                outcomes = [future.result() for future in futures]
            require({(item["status"], item["reason"]) for item in outcomes} ==
                    {(200, "version_rotated"), (403, "wrong_version")}, "competing rotations did not serialize")
        else:
            expired = guard.approve_rotation("operator", "brief", 1, time.time() - 1)
            expired_result = rotate("A", expired)
            if observer:
                observer.poll("After expired approval, before valid rotation", [expired_result])
            outcomes = [expired_result, rotate("A", approval), rotate("B", approval)]
            require([(item["status"], item["reason"]) for item in outcomes] ==
                    [(403, "approval_expired"), (200, "version_rotated"), (403, "approval_missing")],
                    "approval expiry or single-use invariant failed")
        after = [read(node, version) for node in ports for version in (1, 2)]
        require(all((item["status"], item["reason"]) ==
                    ((200, "read") if item["requested_version"] == 2 else (403, "wrong_version"))
                    for item in after), "workers disagree on the surviving version")
        audit = {event["request_id"]: event for event in guard.evidence(admin)}
        evidence = []
        for outcome in outcomes:
            event = audit.get(outcome["request_id"])
            require(event is not None and event["node"] == outcome["node"]
                    and event["reason"] == outcome["reason"]
                    and event["allowed"] == (outcome["status"] == 200), "rotation audit mismatch")
            evidence.append(event)
        if observer:
            observer.poll("After approval and retired-version checks",
                          [item for item in outcomes + after if item["status"] == 403])
        return dict(before=before, after=after, outcomes=outcomes, evidence=evidence,
                    monitor=observer.result() if observer else None)


LAB_SCENARIOS = ("revocation", "approval", "competing", "pre", "post", "backup", "quarantine", "passport")


def assurance_lab(name, challenge=None):
    if name not in LAB_SCENARIOS:
        raise ValueError("unknown lab scenario")
    if name in ("approval", "competing"):
        observations = approval_lab(competing=name == "competing")
    elif name == "quarantine":
        observations = time_machine()
    else:
        result = run("pre" if name == "pre" else "post", challenge_hex=challenge,
                     verify_modified=name == "passport")
        if name == "passport":
            observations = {node: {"statement": record["passport"], **record["verification"]}
                            for node, record in result["nodes"].items()}
        elif name == "revocation":
            observations = {node: {
                "denial_status": record["revoked_status"], "denial_reason": record["revoked_reason"],
                "teammate_status": record["teammate_status"], "statement": record["passport"],
            } for node, record in result["nodes"].items()}
        elif name == "backup":
            observations = {**result["backup"],
                            "evidence": [event for event in result["timeline"]
                                         if event["label"] == "Damaged key backup rejected"]}
        else:
            observations = {key: result[key] for key in ("before", "active_version", "nodes",
                                                         "recovery_ms", "cutoff", "timeline")}
    response = {"scenario": name, "status": "PASS", "observations": observations}
    if name == "passport":
        response["claims"] = result["claim_results"]
    return response


def operational_monitor(publish):
    reports = {}
    for fixture, execute in (
        ("recovery", lambda send: run("post", publish_audit=send)),
        ("approval", lambda send: approval_lab(False, publish_audit=send)),
    ):
        publish({"type": "fixture_started", "fixture": fixture})
        result = execute(lambda event: publish({**event, "fixture": fixture}))
        report = result["monitor"]
        reports[fixture] = report
        if report["status_events"]:
            continue
        require(report["findings"], "monitor received no authenticated denials")
        require(all(item["containment"] == "CONFIRMED_DENIAL_NO_BODY"
                    for item in report["findings"]), "monitor could not correlate a contained denial")
    return reports
