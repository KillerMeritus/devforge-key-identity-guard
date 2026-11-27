import base64
from itertools import product
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, closing
import json
import random
from pathlib import Path
import secrets
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import uvicorn

from demo_cli import WORKER, call, start, wait_for
from kig_core.archive import Archive, ArchiveDenied, ArchiveUnavailable
from kig_core.guard import Guard
from kig_core.worker_archive import ArchivedGuard, open_archive, provision_archive
from kig_core.witness import RevocationWitness
from node_server import worker


class ArchiveWorkerTest(unittest.TestCase):
    def setUp(self):
        self.state = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.working_path = self.state / "demo.sqlite"
        keys = [secrets.token_bytes(32) for _ in range(3)]
        for name, key in zip(("audit", "storage", "backup"), keys):
            (self.state / f"{name}.key").write_bytes(key)
        witness_path = self.state / "witness" / "checkpoint.sqlite"
        witness_path.parent.mkdir()
        witness = RevocationWitness(witness_path, keys[0])
        witness.provision()
        self.guard = Guard(self.working_path, *keys, witness=witness)
        self.operator = self.guard.enroll("operator", "admin")
        self.supervisor = self.guard.enroll("supervisor", "admin")
        self.reader = self.guard.enroll("reader")
        self.guard.seed_file("brief", b"synthetic rotation input", "reader")
        self.approvals = [self.guard.approve_rotation("operator", "brief", 1, time.time() + 120)
                          for _ in range(2)]
        self.before_provision = self.state / "baseline-snapshot.sqlite"
        with closing(sqlite3.connect(self.working_path)) as live, closing(
            sqlite3.connect(self.before_provision)
        ) as snapshot:
            live.backup(snapshot)
        self.archive_credentials = provision_archive(self.state, self.guard)

    def assert_startup_refused(self, state, node, message, *, archive=False):
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        command = [sys.executable, str(WORKER), "--state", str(state), "--node", node,
                   "--port", str(port)]
        if archive:
            command.append("--archive")
        process = subprocess.run(command, capture_output=True, text=True, timeout=5)
        self.assertEqual(process.returncode, 1, process.stderr)
        self.assertIn(message, process.stderr)

    def test_archive_binding_refuses_baseline_worker_after_preprovision_restore(self):
        with ExitStack() as stack:
            a, _ = start(stack, self.state, "A", self.state / "worker-a.log", archive=True)
            self.assertEqual(self.read(a, 1)[0], 200)
            self.assert_startup_refused(self.state, "B", "archive enforcement required")
        with closing(sqlite3.connect(self.before_provision)) as snapshot, closing(
            sqlite3.connect(self.working_path)
        ) as live:
            snapshot.backup(live)
        for node in ("A", "B"):
            self.assert_startup_refused(self.state, node, "archive enforcement required")
        with ExitStack() as stack:
            a, _ = start(stack, self.state, "A", self.state / "stale-a.log", archive=True)
            self.assertEqual(self.read(a, 1), (503, {"error": "audit_state_unavailable"}))

    def test_older_archive_directory_still_binds_execution_mode(self):
        (self.state / "archive.required").unlink()
        self.assert_startup_refused(self.state, "B", "archive enforcement required")
        with ExitStack() as stack:
            a, _ = start(stack, self.state, "A", self.state / "worker-a.log", archive=True)
            self.assertEqual(self.read(a, 1)[0], 200)

    def test_archive_worker_refuses_separately_provisioned_baseline_state(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            baseline = Path(directory)
            for name in ("audit", "storage", "backup"):
                (baseline / f"{name}.key").write_bytes((self.state / f"{name}.key").read_bytes())
            witness = baseline / "witness" / "checkpoint.sqlite"
            witness.parent.mkdir()
            RevocationWitness(witness, self.guard.audit_key).provision()
            with closing(sqlite3.connect(self.before_provision)) as snapshot, closing(
                sqlite3.connect(baseline / "demo.sqlite")
            ) as live:
                snapshot.backup(live)
            self.assert_startup_refused(baseline, "A", "archive execution mode binding unavailable",
                                        archive=True)
            for node in ("A", "B"):
                port, _ = start(stack, baseline, node, baseline / f"{node}.log")
                self.assertEqual(self.read(port, 1)[0], 200)

    def test_historical_denial_preserves_application_reason_and_resource_presence(self):
        coordinator = ArchivedGuard(self.guard, self.state, "A")
        coordinator.execute(self.supervisor, "revoke", self.guard.digest(self.reader),
                            idempotency_key="revoke-reader")
        for credential, reason in ((self.reader, "revoked_device"), ("invalid", "invalid_device"),
                                   (self.operator, "missing_grant")):
            for target, present in (("brief", True), ("unrecognized target", False)):
                with self.subTest(reason=reason, target=target):
                    decision = coordinator.execute(credential, "read", target, version=1)
                    event_id = decision["request_id"]
                    retained = coordinator.archive.retrieve(
                        self.archive_credentials["investigator"], "worker-A", event_id,
                    )
                    event = json.loads(retained["event_bytes"])
                    self.assertEqual(event["reason"], reason)
                    self.assertEqual(event["reason"], decision["reason"])
                    self.assertIs(event["resource_present"], present)
                    if not present:
                        self.assertNotEqual(event["entity_id"], target)
                        absence = retained["intent_receipt"]["expected"]["entities"]
                        self.assertEqual({e["kind"] for e in absence if e["version"] == 0},
                                         {"asset", "grant"})
                    with closing(sqlite3.connect(self.working_path)) as db:
                        audit = self.guard.audit(db)[-1]
                    self.assertEqual(audit["request_id"], event_id)
                    self.assertEqual(audit["reason"], reason)

    def rotate(self, port, operation, approval):
        fields = {"target": "brief", "version": 1, "approval": approval}
        return call(port, "rotate", self.operator, fields, idempotency_key=operation)[:2]

    def active_state(self):
        with closing(sqlite3.connect(self.working_path)) as db:
            version, = db.execute("SELECT version FROM files WHERE id='brief'").fetchone()
            approvals = {row[0] for row in db.execute("SELECT id FROM approvals")}
        return version, approvals

    def read(self, port, version):
        return call(port, "read", self.reader, {"target": "brief", "version": version})[:2]

    def crash_rotation(self, stack, phase):
        log = self.state / "worker-a.log"
        a, process = start(stack, self.state, "A", log, checkpoint=phase, archive=True)
        b, _ = start(stack, self.state, "B", self.state / "worker-b.log", archive=True)
        pool = stack.enter_context(ThreadPoolExecutor(max_workers=1))
        operation = "rotation-ack-lost"
        pending = pool.submit(self.rotate, a, operation, self.approvals[0])
        try:
            wait_for(lambda: "CHECKPOINT prepared" in log.read_text(), "prepared rotation")
            for _ in range(5):
                self.assertEqual(self.read(b, 1)[0], 200)
            self.assertFalse(pending.done())
            (self.state / "resume-rotation").touch()
            wait_for(lambda: f"CHECKPOINT {phase}" in log.read_text().splitlines(), phase)
            if phase == "post":
                for _ in range(5):
                    self.assertEqual(self.read(b, 2)[0], 200)
            self.assertFalse(pending.done())
        finally:
            process.kill()
            self.assertEqual(process.wait(timeout=5), -signal.SIGKILL)
        with self.assertRaises(OSError):
            pending.result()
        a, _ = start(stack, self.state, "A", self.state / "worker-a-restarted.log", archive=True)
        return a, b, operation

    def test_precommit_kill_without_positive_noncommit_quarantines_both_workers(self):
        with ExitStack() as stack:
            a, b, operation = self.crash_rotation(stack, "pre")
            self.assertEqual(self.active_state(), (1, set(self.approvals)))
            for port in (a, b):
                status, result = self.read(port, 1)
                self.assertEqual(status, 503)
                self.assertEqual(result, {"error": "recovery_pending"})
            self.assertEqual(self.rotate(a, operation, self.approvals[0])[0], 503)
            archive = open_archive(self.state)
            with archive.verified(write=False) as (_, records, _, _):
                pending = records[-1]
                self.assertEqual(pending["state"], "PENDING")
            coordinator = ArchivedGuard(self.guard, self.state, "B")
            with self.assertRaises(ArchiveUnavailable):
                coordinator.authorize_recovery("independent-recovery", pending["tag"],
                                               secrets.token_urlsafe(32),
                                               expires_ms=archive.now() + 1000)

    def test_postconfirmation_kill_replays_acknowledgement_without_second_mutation(self):
        with ExitStack() as stack:
            a, b, operation = self.crash_rotation(stack, "post")
            first_status, first = self.rotate(a, operation, self.approvals[0])
            second_status, second = self.rotate(b, operation, self.approvals[0])
            self.assertEqual((first_status, second_status), (200, 200))
            self.assertEqual((first["reason"], first["version"]), ("version_rotated", 2))
            self.assertEqual(first["request_id"], second["request_id"])
            conflict, _ = self.rotate(b, operation, self.approvals[1])
            self.assertEqual(conflict, 409)
            self.assertEqual(self.active_state(), (2, {self.approvals[1]}))
            for port in (a, b):
                self.assertEqual(self.read(port, 2)[0], 200)

    def test_recovery_after_producer_expiry_uses_persisted_commit_and_separate_actor(self):
        with ExitStack() as stack:
            a, b, operation = self.crash_rotation(stack, "committed")
            self.assertEqual(self.active_state(), (2, {self.approvals[1]}))
            for port in (a, b):
                status, result = self.read(port, 2)
                self.assertEqual(status, 503)
                self.assertNotIn("body", result)

            archive = open_archive(self.state)
            producer_token = self.archive_credentials["producer-A"]
            with archive.verified(write=False) as (db, records, _, _):
                pending = records[-1]
                self.assertEqual(pending["state"], "PENDING")
                self.assertEqual(pending["event"]["kind"], "rotation")
                producer = archive.authorize(db, producer_token, "producer")

            coordinator = ArchivedGuard(self.guard, self.state, "B")
            recovery_token = secrets.token_urlsafe(32)
            expired_at = producer["expires_ms"]
            with patch.object(Archive, "now", return_value=expired_at):
                with self.assertRaises(ArchiveDenied):
                    archive.position(producer_token)
                with self.assertRaises(ArchiveDenied):
                    coordinator.recover(recovery_token, pending["tag"])
                coordinator.authorize_recovery("independent-recovery", pending["tag"],
                                               recovery_token, expires_ms=expired_at + 1000)
                coordinator.recover(recovery_token, pending["tag"])

            with archive.verified(write=False) as (_, records, _, _):
                terminal = records[-1]
                self.assertEqual(terminal["state"], "CONFIRMED")
                self.assertEqual(terminal["producer"], pending["producer"])
                self.assertEqual(terminal["recovery_actor"], "independent-recovery")
            status, retried = self.rotate(a, operation, self.approvals[0])
            self.assertEqual(status, 200)
            self.assertEqual(retried["request_id"], pending["operation_id"])
            for port in (a, b):
                self.assertEqual(self.read(port, 2)[0], 200)

    def test_workers_serialize_competing_rotations(self):
        with ExitStack() as stack:
            a, _ = start(stack, self.state, "A", self.state / "worker-a.log", archive=True)
            b, _ = start(stack, self.state, "B", self.state / "worker-b.log", archive=True)
            pool = stack.enter_context(ThreadPoolExecutor(max_workers=2))
            futures = [pool.submit(self.rotate, port, f"competing-{node}", approval)
                       for port, node, approval in zip((a, b), ("A", "B"), self.approvals)]
            statuses = [future.result()[0] for future in futures]
            self.assertEqual(sorted(statuses), [200, 403])
            unused_approval = self.approvals[statuses.index(403)]
            self.assertEqual(self.active_state(), (2, {unused_approval}))
            for port in (a, b):
                self.assertEqual(self.read(port, 2)[0], 200)

    def test_revoked_operator_cannot_use_routes_or_replay_successful_mutations(self):
        (self.state / "attestation-A.key").write_bytes(secrets.token_bytes(32))
        with ExitStack() as stack:
            a, _ = start(stack, self.state, "A", self.state / "worker-a.log", archive=True)
            b, _ = start(stack, self.state, "B", self.state / "worker-b.log", archive=True)
            fields = {"target": "reader"}
            self.assertEqual(call(a, "enroll", self.operator, fields)[0], 400)
            status, enrolment, _ = call(a, "enroll", self.operator, fields,
                                        idempotency_key="replacement")
            self.assertEqual(status, 200)
            status, replay, _ = call(b, "enroll", self.operator, fields,
                                     idempotency_key="replacement")
            self.assertEqual(status, 200)
            self.assertEqual(replay["device_ref"], self.guard.digest(enrolment["token"]))
            self.assertEqual(replay["request_id"], enrolment["request_id"])
            self.assertNotEqual(replay["device_ref"], self.guard.digest(self.reader))
            self.assertNotIn("token", replay)

            status, rotation = self.rotate(a, "previous-rotation", self.approvals[0])
            self.assertEqual(status, 200)
            event = f"evidence/{rotation['request_id']}"
            challenge = {"challenge": secrets.token_hex(32)}
            self.assertEqual(call(a, event + "/attestation", self.operator, challenge)[0], 200)
            status, _, _ = call(b, "revoke", self.supervisor,
                                {"target": self.guard.digest(self.operator)},
                                idempotency_key="operator-revocation")
            self.assertEqual(status, 200)
            for port in (a, b):
                operations = (
                    ("read", {"target": "brief", "version": 2}, None),
                    ("rotate", {"target": "brief", "version": 1, "approval": self.approvals[0]},
                     "previous-rotation"),
                    ("revoke", {"target": self.guard.digest(self.reader)}, "reader-revocation"),
                    ("enroll", fields, "replacement"),
                    ("enroll", fields, "new-enrolment"),
                    (event, None, None),
                    (event + "/attestation", challenge, None),
                )
                for route, payload, key in operations:
                    with self.subTest(port=port, route=route, key=key):
                        status, body, _ = call(port, route, self.operator, payload, idempotency_key=key)
                        self.assertEqual(status, 403)
                        self.assertTrue({"body", "token", "proof", "signature"}.isdisjoint(body))
                self.assertEqual(self.read(port, 2)[0], 200)

    def test_workers_withhold_content_when_archive_is_missing_or_corrupted(self):
        archive_path = self.state / "archive" / "audit.sqlite"
        with ExitStack() as stack:
            ports = [start(stack, self.state, node, self.state / f"worker-{node}.log",
                           archive=True)[0] for node in ("A", "B")]
            self.assertEqual(self.read(ports[0], 1)[0], 200)
            saved = archive_path.with_name("retained.sqlite")
            archive_path.rename(saved)
            for port in ports:
                with self.subTest(node_port=port, failure="missing archive"):
                    status, result = self.read(port, 1)
                    self.assertEqual(status, 503)
                    self.assertNotIn("body", result)
            self.assertFalse(archive_path.exists())
            saved.rename(archive_path)
            with closing(sqlite3.connect(archive_path)) as db, db:
                db.execute("UPDATE head SET proof='corrupted'")
            for port in ports:
                with self.subTest(node_port=port, failure="corrupted archive"):
                    status, result = self.read(port, 1)
                    self.assertEqual(status, 503)
                    self.assertNotIn("body", result)

    def test_archive_capacity_withholds_later_protected_response(self):
        # Exercise the real HTTP handler with a small capacity so the fixture
        # needs only one complete receipt instead of hundreds of verified writes.
        with ExitStack() as stack:
            reserved = stack.enter_context(socket.socket())
            reserved.bind(("127.0.0.1", 0))
            port = reserved.getsockname()[1]
            stack.enter_context(patch("kig_core.archive.MAX_RECORDS", 2))
            pool = stack.enter_context(ThreadPoolExecutor(max_workers=1))
            app = worker(self.state, "A", archive=True)
            server = uvicorn.Server(uvicorn.Config(app, log_level="error"))
            running = pool.submit(server.run, sockets=[reserved])
            try:
                wait_for(lambda: server.started or running.done(), "capacity fixture worker")
                self.assertFalse(running.done())
                self.assertEqual(self.read(port, 1)[0], 200)
                status, result = self.read(port, 1)
                self.assertEqual(status, 503)
                self.assertNotIn("body", result)
            finally:
                server.should_exit = True
                running.result(timeout=5)

    def test_actual_persisted_rows_verified_even_with_genuine_history(self):
        with ExitStack() as stack:
            a, _ = start(stack, self.state, "A", self.state / "worker-a.log", archive=True)
            b, _ = start(stack, self.state, "B", self.state / "worker-b.log", archive=True)
            self.assertEqual(self.rotate(a, "tamper-guard", self.approvals[0])[0], 200)
            self.assertEqual(self.read(b, 2)[0], 200)
            with closing(sqlite3.connect(self.working_path)) as db, db:
                db.execute("DELETE FROM grants WHERE actor='reader' AND file='brief'")
            for port in (a, b):
                status, result = self.read(port, 2)
                self.assertEqual(status, 503)
                self.assertNotIn("body", result)

    def test_verified_export_restores_missing_working_store_and_refuses_stale_rotation(self):
        coordinator = ArchivedGuard(self.guard, self.state)
        stale = self.state / "pre-rotation.sqlite"
        current = self.state / "current.sqlite"
        cli = Path(WORKER).with_name("archive_ops.py")
        exported = subprocess.run(
            [sys.executable, str(cli), "--state", str(self.state), "export", str(stale)],
            capture_output=True, text=True, check=True, timeout=10,
        )
        self.assertEqual(json.loads(exported.stdout)["status"], "verified_encrypted_snapshot_exported")
        self.assertEqual(stale.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(b"synthetic rotation input", stale.read_bytes())
        with self.assertRaises(FileExistsError):
            coordinator.export_verified(stale)

        with ExitStack() as stack:
            a, _ = start(stack, self.state, "A", self.state / "export-a.log", archive=True)
            self.assertEqual(self.rotate(a, "backup-rotation", self.approvals[0])[0], 200)
        coordinator.export_verified(current)
        with self.assertRaises(ArchiveUnavailable):
            coordinator.restore_verified(stale)

        with closing(sqlite3.connect(stale)) as old, closing(sqlite3.connect(self.working_path)) as live:
            old.backup(live)
        with ExitStack() as stack:
            for node in ("A", "B"):
                port, _ = start(stack, self.state, node, self.state / f"rolled-back-{node}.log",
                                archive=True)
                status, response = self.read(port, 1)
                self.assertEqual(status, 503)
                self.assertNotIn("body", response)
        coordinator.restore_verified(current)

        # Test each integrity domain with genuine audit metadata retained.
        for mutation, values in (
            ("UPDATE devices SET role='admin' WHERE token=?", (self.guard.digest(self.reader),)),
            ("DELETE FROM grants WHERE actor='reader' AND file='brief'", ()),
            ("UPDATE approvals SET version=2 WHERE id=?", (self.approvals[1],)),
            ("UPDATE files SET body=? WHERE id='brief'", (b"corrupt",)),
        ):
            with self.subTest(mutation=mutation):
                with closing(sqlite3.connect(self.working_path)) as db, db:
                    self.assertEqual(db.execute(mutation, values).rowcount, 1)
                with self.assertRaises(ArchiveUnavailable):
                    coordinator.export_verified(self.state / "refused.sqlite")
                self.assertFalse((self.state / "refused.sqlite").exists())
                coordinator.restore_verified(current)

        self.working_path.unlink()
        restored = subprocess.run(
            [sys.executable, str(cli), "--state", str(self.state), "restore", str(current)],
            capture_output=True, text=True, check=True, timeout=10,
        )
        self.assertEqual(json.loads(restored.stdout)["status"], "verified_snapshot_restored")
        self.assertEqual(self.active_state(), (2, {self.approvals[1]}))
        with ExitStack() as stack:
            for node in ("A", "B"):
                port, _ = start(stack, self.state, node, self.state / f"recovered-{node}.log", archive=True)
                old_status, old_result = self.read(port, 1)
                status, result = self.read(port, 2)
                self.assertEqual((old_status, old_result["reason"]), (403, "wrong_version"))
                self.assertEqual(status, 200)
                self.assertEqual(base64.b64decode(result["body"]), b"synthetic rotation input")

    def test_two_worker_access_decisions_match_reference_model(self):
        # The model is built from fixture policy. It never reads the service database.
        roles = {"reader": self.reader, "operator": self.operator, "unregistered": "unregistered"}
        with ExitStack() as stack:
            ports = [start(stack, self.state, node, self.state / f"model-{node}.log", archive=True)[0]
                     for node in ("A", "B")]
            for active_version in (1, 2):
                if active_version == 2:
                    self.assertEqual(self.rotate(ports[0], "model-rotation", self.approvals[0])[0], 200)
                for port, actor, version in product(ports, roles, (1, 2)):
                    expected = (
                        (401, "invalid_device") if actor == "unregistered" else
                        (403, "missing_grant") if actor == "operator" else
                        (403, "wrong_version") if version != active_version else (200, "read")
                    )
                    status, body, _ = call(port, "read", roles[actor], {"target": "brief", "version": version})
                    self.assertEqual((status, body["reason"]), expected)
                    self.assertEqual("body" in body, status == 200)
            self.assertEqual(call(ports[1], "revoke", self.operator, {"target": self.guard.digest(self.reader)},
                                  idempotency_key="model-revoke")[0], 200)
            for port, version in product(ports, (1, 2)):
                status, body = self.read(port, version)
                self.assertEqual((status, body["reason"]), (403, "revoked_device"))
                self.assertNotIn("body", body)

    def test_seeded_worker_transitions_match_fixture_policy(self):
        for seed in (1729, 9043):
            with self.subTest(seed=seed), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                state = Path(directory)
                keys = [secrets.token_bytes(32) for _ in range(3)]
                for label, key in zip(("audit", "storage", "backup"), keys):
                    (state / f"{label}.key").write_bytes(key)
                witness_file = state / "witness" / "checkpoint.sqlite"
                witness_file.parent.mkdir()
                witness = RevocationWitness(witness_file, keys[0])
                witness.provision()
                guard = Guard(state / "demo.sqlite", *keys, witness=witness)
                actors = {name: guard.enroll(name, "admin" if name == "admin" else "reader")
                          for name in ("admin", "reader", "peer")}
                body = b"independent model fixture"
                guard.seed_file("brief", body, "reader", "peer")
                approvals = {version: guard.approve_rotation("admin", "brief", version, time.time() + 120)
                             for version in range(1, 4)}
                provision_archive(state, guard)
                ports = [start(stack, state, node, state / f"{node}.log", archive=True)[0]
                         for node in ("A", "B")]
                rng = random.Random(seed)
                version, consumed, revoked = 1, set(), set()
                chunks = [
                    [("rotate", "reader", 1), ("rotate", "admin", 2), ("read", "peer", 1)],
                    [("rotate", "admin", 1)],
                    [("read", "reader", 1), ("read", "peer", 2), ("rotate", "admin", 1)],
                    [("revoke", "admin", "reader")],
                    [("read", "reader", 2), ("read", "peer", 2), ("revoke", "peer", "peer")],
                    [("rotate", "admin", 2)],
                    [("read", "admin", 3), ("read", "peer", 3), ("read", "reader", 3)],
                ]
                operations = []
                for items in chunks:
                    items += [("read", rng.choice(tuple(actors)), rng.randint(1, 4)) for _ in range(5)]
                    rng.shuffle(items)
                    operations.extend(items)
                for index, (operation, actor, parameter) in enumerate(operations):
                    fields = {"target": "brief"}
                    if operation == "read":
                        fields["version"] = parameter
                        reason = ("revoked_device" if actor in revoked else
                                  "missing_grant" if actor == "admin" else
                                  "wrong_version" if parameter != version else "read")
                    elif operation == "rotate":
                        fields.update(version=1 if parameter == 2 and version == 1 else parameter,
                                      approval=approvals[parameter])
                        if actor != "admin":
                            reason = "action_forbidden"
                        elif parameter in consumed:
                            reason = "approval_missing"
                        elif fields["version"] != parameter:
                            reason = "approval_version_mismatch"
                        else:
                            self.assertEqual(version, parameter)
                            reason, version = "version_rotated", version + 1
                            consumed.add(parameter)
                    else:
                        fields["target"] = Guard.digest(actors[parameter])
                        reason = "revoked" if actor == "admin" else "action_forbidden"
                        if reason == "revoked":
                            revoked.add(parameter)
                    status, result, _ = call(ports[rng.randrange(2)], operation, actors[actor], fields,
                                             idempotency_key=f"seed-{seed}-{index}")
                    with self.subTest(seed=seed, index=index, operation=operation):
                        self.assertEqual((status, result.get("reason")),
                                         (200 if reason in {"read", "version_rotated", "revoked"} else 403, reason))
                        if reason == "read":
                            self.assertEqual(base64.b64decode(result["body"]), body)
                        else:
                            self.assertNotIn("body", result)
                self.assertEqual((version, consumed, revoked), (3, {1, 2}, {"reader"}))

    def test_real_sigkill_during_missing_store_restore(self):
        coordinator = ArchivedGuard(self.guard, self.state)
        backup = self.state / "restore-input.sqlite"
        coordinator.export_verified(backup)
        self.working_path.unlink()
        child_script = """
import os
from pathlib import Path
import signal
import sys
from archive_ops import existing_guard
from kig_core.worker_archive import ArchivedGuard
state, snapshot = map(Path, sys.argv[1:3])
link = os.link

def pause_link(source, destination):
    if sys.argv[3] == "after-publication":
        link(source, destination)
    print("RESTORE CHECKPOINT", flush=True)
    signal.pause()

os.link = pause_link
ArchivedGuard(existing_guard(state), state).restore_verified(snapshot)
"""
        for boundary in ("before-publication", "after-publication"):
            with self.subTest(boundary=boundary):
                child_log = self.state / f"{boundary}.log"
                with child_log.open("w") as log, subprocess.Popen(
                    [sys.executable, "-c", child_script, str(self.state), str(backup), boundary],
                    stdout=log, stderr=subprocess.STDOUT,
                ) as child:
                    try:
                        wait_for(lambda: "RESTORE CHECKPOINT" in child_log.read_text() or child.poll() is not None,
                                 "restoration publication boundary")
                        self.assertIsNone(child.poll(), child_log.read_text())
                    finally:
                        if child.poll() is None:
                            child.kill()
                        child.wait(timeout=5)
                    self.assertEqual(child.returncode, -signal.SIGKILL)
                with ExitStack() as stack:
                    port, _ = start(stack, self.state, "A", self.state / f"{boundary}-worker.log", archive=True)
                    status, result = self.read(port, 1)
                    if boundary == "before-publication":
                        self.assertEqual(status, 503)
                        self.assertNotIn("body", result)
                    else:
                        self.assertEqual(status, 200)
                        self.assertEqual(base64.b64decode(result["body"]), b"synthetic rotation input")

    def test_read_receipt_keeps_older_snapshot_ineligible(self):
        coordinator = ArchivedGuard(self.guard, self.state)
        snapshot = self.state / "before-read.sqlite"
        coordinator.export_verified(snapshot)
        with ExitStack() as stack:
            port, _ = start(stack, self.state, "A", self.state / "read-eligibility.log", archive=True)
            self.assertEqual(self.read(port, 1)[0], 200)
        with self.assertRaises(ArchiveUnavailable):
            coordinator.restore_verified(snapshot)
        self.assertEqual(self.active_state(), (1, set(self.approvals)))

    def test_real_sigkill_inside_sqlite_restore_copy(self):
        coordinator = ArchivedGuard(self.guard, self.state)
        backup = self.state / "copy-input.sqlite"
        coordinator.export_verified(backup)
        with closing(sqlite3.connect(self.working_path)) as db, db:
            db.execute("UPDATE files SET body=? WHERE id='brief'", (b"damaged fixture",))
        child_script = """
from pathlib import Path
import signal
import sqlite3
import sys
from archive_ops import existing_guard
from kig_core.worker_archive import ArchivedGuard
state, snapshot = map(Path, sys.argv[1:3])
connect = sqlite3.connect

class PausedBackup(sqlite3.Connection):
    def backup(self, target, *, pages, progress, sleep):
        def checkpoint(status, remaining, total):
            progress(status, remaining, total)
            if remaining > 0:
                print("RESTORE COPY IN PROGRESS", flush=True)
                signal.pause()
        return super().backup(target, pages=1, progress=checkpoint, sleep=sleep)

def connect_with_pause(path, *args, **kwargs):
    if str(path) == snapshot.as_uri() + "?mode=ro":
        kwargs["factory"] = PausedBackup
    return connect(path, *args, **kwargs)

sqlite3.connect = connect_with_pause
ArchivedGuard(existing_guard(state), state).restore_verified(snapshot)
"""
        child_log = self.state / "restore-copy.log"
        with child_log.open("w") as log, subprocess.Popen(
            [sys.executable, "-c", child_script, str(self.state), str(backup)],
            stdout=log, stderr=subprocess.STDOUT,
        ) as child:
            try:
                wait_for(lambda: "RESTORE COPY IN PROGRESS" in child_log.read_text() or child.poll() is not None,
                         "SQLite restore page copy")
                self.assertIsNone(child.poll(), child_log.read_text())
            finally:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=5)
            self.assertEqual(child.returncode, -signal.SIGKILL)
        with ExitStack() as stack:
            port, _ = start(stack, self.state, "B", self.state / "copy-worker-failed.log", archive=True)
            status, result = self.read(port, 1)
            self.assertEqual(status, 503)
            self.assertNotIn("body", result)
        coordinator.restore_verified(backup)
        with ExitStack() as stack:
            port, _ = start(stack, self.state, "B", self.state / "copy-worker-retried.log", archive=True)
            status, result = self.read(port, 1)
            self.assertEqual(status, 200)
            self.assertEqual(base64.b64decode(result["body"]), b"synthetic rotation input")
