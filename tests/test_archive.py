from contextlib import closing
import base64
import json
import os
from pathlib import Path
import secrets
import selectors
import signal
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from kig_core.archive import (
    GENESIS, Archive, ArchiveConflict, ArchiveDenied, ArchiveUnavailable, canonical,
)


CHILD = """
import base64, json, os, sys, time
from kig_core.archive import Archive, ArchiveConflict, GENESIS, canonical
config = json.loads(sys.stdin.readline())
archive = Archive(config["path"], "fixture", receipt_key=bytes.fromhex(config["receipt"]),
                  grant_key=bytes.fromhex(config["grant"]))
if config.get("gate"):
    from pathlib import Path
    while not Path(config["gate"]).exists():
        time.sleep(.005)
try:
    record = archive.append_intent(config["token"], config["id"],
                                   base64.b64decode(config["event"]),
                                   predecessor=GENESIS, deadline_ms=config["deadline"],
                                   expected={"version": 1, "digest": "a" * 64})
except ArchiveConflict:
    print("conflict", flush=True)
else:
    print(record["tag"], flush=True)
    if config.get("wait"):
        time.sleep(60)
"""


class ArchiveTest(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.path = self.directory / "archive.sqlite"
        self.keys = {"receipt_key": secrets.token_bytes(32), "grant_key": secrets.token_bytes(32)}
        self.archive = Archive(self.path, "fixture", **self.keys)
        self.producer, self.investigator, self.expired, self.revoked, self.narrow = (
            secrets.token_urlsafe(32) for _ in range(5)
        )
        self.deadline = self.archive.now() + 60_000
        investigator = dict(principal="investigator", role="investigator", scopes=["rotation"],
                            expires_ms=self.deadline, revoked=False)
        self.archive.provision({
            self.producer: {**investigator, "principal": "worker-A", "role": "producer"},
            self.investigator: investigator,
            self.expired: {**investigator, "expires_ms": 0},
            self.revoked: {**investigator, "revoked": True},
            self.narrow: {**investigator, "scopes": ["revocation"]},
        })
        self.event = dict(version=1, event_id="event-1", request_id="request-1",
                          principal="fixture-user", node="A", kind="rotation", entity_id="brief",
                          result="deny", reason="action_forbidden", received_ms=1, source_ids=[])
        self.outcome = dict(basis="verified_commit", entity_id="brief", before_version=1,
                            after_version=1, before_digest="a" * 64, after_digest="a" * 64)

    def intent(self, event=None, operation="operation-1", predecessor=GENESIS):
        return self.archive.append_intent(self.producer, operation, canonical(event or self.event),
                                          predecessor=predecessor, deadline_ms=self.deadline,
                                          expected={"version": 1, "digest": "a" * 64})

    def test_canonical_event_and_scoped_historical_evidence(self):
        raw = canonical(self.event)
        self.assertEqual(raw, b'{"entity_id":"brief","event_id":"event-1","kind":"rotation",'
                         b'"node":"A","principal":"fixture-user","reason":"action_forbidden",'
                         b'"received_ms":1,"request_id":"request-1","result":"deny",'
                         b'"source_ids":[],"version":1}')
        pending = self.intent()
        confirmed = self.archive.finalize(self.producer, pending["tag"], self.outcome)
        self.assertEqual((pending["state"], confirmed["state"]), ("PENDING", "CONFIRMED"))
        self.assertEqual(confirmed["predecessor"], pending["tag"])
        for token in ("", self.producer, self.expired, self.revoked, self.narrow):
            with self.subTest(token_type=token == self.producer):
                with self.assertRaises(ArchiveDenied):
                    self.archive.retrieve(token, "worker-A", "event-1")
        retained = self.archive.retrieve(self.investigator, "worker-A", "event-1")
        self.assertEqual(retained["event_bytes"], raw)
        self.assertEqual(retained["terminal_receipt"], confirmed)

    def test_retries_conflicts_and_abort(self):
        pending = self.intent()
        self.assertEqual(self.intent(), pending)
        self.assertEqual(self.archive.position(self.producer)["pending"], pending)
        with self.assertRaises(ArchiveConflict):
            self.intent({**self.event, "reason": "other"})
        with self.assertRaises(ArchiveConflict):
            self.intent(operation="other", predecessor=pending["tag"])
        with self.assertRaises(ValueError):
            self.archive.finalize(self.producer, pending["tag"], {**self.outcome, "basis": "unknown"})
        self.assertEqual(self.archive.position(self.producer)["pending"], pending)
        with self.assertRaises(ValueError):
            self.archive.finalize(self.producer, pending["tag"],
                                  {**self.outcome, "basis": "verified_noncommit", "after_version": 2})
        with self.assertRaises(ArchiveConflict):
            self.archive.finalize(self.producer, pending["tag"],
                                  {**self.outcome, "before_digest": "b" * 64})
        abort = {**self.outcome, "basis": "verified_noncommit"}
        terminal = self.archive.finalize(self.producer, pending["tag"], abort)
        self.assertEqual(terminal["state"], "ABORTED")
        self.assertEqual(self.archive.finalize(self.producer, pending["tag"], abort), terminal)
        self.assertEqual(self.intent(), pending)
        self.assertEqual(self.archive.position(self.producer)["sequence"], 2)
        with self.assertRaises(ArchiveConflict):
            self.archive.finalize(self.producer, pending["tag"], self.outcome)
        with self.assertRaises(ArchiveConflict):
            self.intent({**self.event, "event_id": "new"}, operation="new", predecessor=pending["tag"])

    def test_schema_rejects_noncanonical_or_extra_data(self):
        raw = canonical(self.event)
        for invalid in (b" " + raw, raw.replace(b'"version":1', b'"version":1,"version":1'),
                        canonical({**self.event, "received_ms": True}),
                        canonical({**self.event, "received_ms": 1.5}),
                        canonical({**self.event, "plaintext": "excluded"}),
                        canonical({**self.event, "kind": "detector_alert"})):
            with self.assertRaises(ValueError):
                self.archive.append_intent(self.producer, "op", invalid, predecessor=GENESIS,
                                           deadline_ms=self.deadline,
                                           expected={"version": 1, "digest": "a" * 64})
        self.assertEqual(self.archive.position(self.producer)["sequence"], 0)

    def test_pin_corruption_and_missing_archive_fail_closed(self):
        with self.assertRaises(FileExistsError):
            self.archive.provision({})
        wrong = Archive(self.path, "other-store", **self.keys)
        with self.assertRaises(ArchiveUnavailable):
            wrong.position(self.producer)
        self.intent()
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("DELETE FROM records")
        with self.assertRaises(ArchiveUnavailable):
            self.archive.position(self.producer)
        self.path.rename(self.directory / "preserved.sqlite")
        with self.assertRaises(ArchiveUnavailable):
            self.archive.position(self.producer)
        self.assertFalse(self.path.exists())

    def test_capacity_preserves_space_to_finalize(self):
        with patch("kig_core.archive.MAX_RECORDS", 2):
            pending = self.intent()
            final = self.archive.finalize(self.producer, pending["tag"], self.outcome)
            with self.assertRaises(ArchiveUnavailable):
                self.intent({**self.event, "event_id": "next"}, operation="next",
                            predecessor=final["tag"])
            self.assertEqual(self.intent(), pending)
            self.assertEqual(self.archive.position(self.producer)["sequence"], 2)

    def start_writer(self, name, *, gate=None, wait=False, operation=None, event=None):
        config = dict(path=str(self.path), receipt=self.keys["receipt_key"].hex(),
                      grant=self.keys["grant_key"].hex(), id=operation or name,
                      token=self.producer, deadline=self.deadline,
                      event=base64.b64encode(canonical(event or {**self.event, "event_id": name})).decode(),
                      gate=str(gate) if gate else None, wait=wait)
        process = subprocess.Popen([sys.executable, "-c", CHILD], cwd=Path(__file__).resolve().parents[1],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)

        def close_child():
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)

        self.addCleanup(close_child)
        process.stdin.write(json.dumps(config) + "\n")
        process.stdin.flush()
        return process

    def test_confirmed_history_and_pending_survive_writer_kill(self):
        child = self.start_writer("event-1", wait=True, operation="operation-1")
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            self.assertTrue(selector.select(timeout=5), "writer did not acknowledge pending")
        tag = child.stdout.readline().strip()
        child.kill()
        self.assertEqual(child.wait(timeout=5), -signal.SIGKILL)
        reopened = Archive(self.path, "fixture", **self.keys)
        self.assertEqual(reopened.position(self.producer)["pending"]["tag"], tag)
        self.assertEqual(reopened.position(self.producer)["pending"]["state"], "PENDING")
        # A lost process never establishes noncommit. This explicit completion is
        # a trusted fixture assertion, standing in for future worker row verification.
        terminal = reopened.finalize(self.producer, tag, self.outcome)
        self.assertEqual(Archive(self.path, "fixture", **self.keys).retrieve(
            self.investigator, "worker-A", "event-1")["terminal_receipt"], terminal)

    def test_concurrent_processes_cannot_commit_forked_history(self):
        gate = self.directory / "start"
        writers = [self.start_writer(f"event-{i}", gate=gate) for i in range(2)]
        gate.touch()
        outputs = []
        for writer in writers:
            out, err = writer.communicate(timeout=8)
            self.assertEqual(writer.returncode, 0, err)
            outputs.append(out.strip())
        self.assertEqual(outputs.count("conflict"), 1)
        pending = self.archive.position(self.producer)["pending"]
        self.assertIn(pending["tag"], outputs)
        final = self.archive.finalize(self.producer, pending["tag"], self.outcome)
        self.assertEqual(final["sequence"], 2)
        self.assertEqual(self.archive.position(self.producer)["tag"], final["tag"])


    def test_concurrent_identical_retries_share_receipt(self):
        gate = self.directory / "retry"
        writers = [self.start_writer("event-1", gate=gate, operation="operation-1")
                   for _ in range(2)]
        gate.touch()
        tags = []
        for writer in writers:
            out, err = writer.communicate(timeout=8)
            self.assertEqual(writer.returncode, 0, err)
            tags.append(out.strip())
        self.assertEqual(tags[0], tags[1])
        position = self.archive.position(self.producer)
        self.assertEqual(position["sequence"], 1)
        self.assertEqual(position["tag"], tags[0])
