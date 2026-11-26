from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, closing
from pathlib import Path
import secrets
import signal
import socket
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

import uvicorn

from demo_cli import call, start, wait_for
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
        self.archive_credentials = provision_archive(self.state, self.guard)

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
                self.assertNotIn("body", result)
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
