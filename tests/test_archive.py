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
                                   expected=config["projection"])
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
        self.projection = {"schema": 1, "entities": [
            {"kind": "approval", "id": "approval-1", "version": 1, "digest": "b" * 64},
            {"kind": "asset", "id": "brief", "version": 2, "digest": "a" * 64},
        ]}
        self.archive.provision({
            self.producer: {**investigator, "principal": "worker-A", "role": "producer",
                            "node": "A", "subsystem": "worker"},
            self.investigator: investigator,
            self.expired: {**investigator, "expires_ms": 0},
            self.revoked: {**investigator, "revoked": True},
            self.narrow: {**investigator, "scopes": ["revocation"]},
        }, initial=self.projection)
        self.event = dict(version=2, event_id="event-1", request_id="request-1",
                          actor="fixture-user", node="A", subsystem="worker", kind="rotation", entity_id="brief",
                          authorization="deny", reason="action_forbidden", received_ms=1, source_ids=[])
        self.outcome = dict(basis="verified_commit", before=self.projection,
                            after=self.projection, delivery="unknown")

    def intent(self, event=None, operation="operation-1", predecessor=GENESIS):
        return self.archive.append_intent(self.producer, operation, canonical(event or self.event),
                                          predecessor=predecessor, deadline_ms=self.deadline,
                                          expected=self.projection)

    def test_canonical_event_and_scoped_historical_evidence(self):
        raw = canonical(self.event)
        self.assertEqual(raw, b'{"actor":"fixture-user","authorization":"deny","entity_id":"brief",'
                         b'"event_id":"event-1","kind":"rotation","node":"A",'
                         b'"reason":"action_forbidden","received_ms":1,"request_id":"request-1",'
                         b'"source_ids":[],"subsystem":"worker","version":2}')
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
                                  {**self.outcome, "before": self.changed_projection()})
        abort = {**self.outcome, "basis": "verified_noncommit", "delivery": "withheld"}
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
        for invalid in (b" " + raw, raw.replace(b'"version":2', b'"version":2,"version":2'),
                        canonical({**self.event, "received_ms": True}),
                        canonical({**self.event, "received_ms": 1.5}),
                        canonical({**self.event, "plaintext": "excluded"}),
                        canonical({**self.event, "kind": "detector_alert"})):
            with self.assertRaises(ValueError):
                self.archive.append_intent(self.producer, "op", invalid, predecessor=GENESIS,
                                           deadline_ms=self.deadline,
                                           expected=self.projection)
        self.assertEqual(self.archive.position(self.producer)["sequence"], 0)

    def test_pin_corruption_and_missing_archive_fail_closed(self):
        with self.assertRaises(FileExistsError):
            self.archive.provision({}, initial=self.projection)
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
            self.assertEqual(self.archive.position(self.producer)["capacity"],
                             {"used": 2, "remaining": 0, "can_accept_intent": False})
            self.assertEqual(self.archive.retrieve(self.investigator, "worker-A", "event-1")
                             ["terminal_receipt"], final)

    def start_writer(self, name, *, gate=None, wait=False, operation=None, event=None):
        config = dict(path=str(self.path), receipt=self.keys["receipt_key"].hex(),
                      grant=self.keys["grant_key"].hex(), id=operation or name, projection=self.projection,
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


    def changed_projection(self):
        return {"schema": 1, "entities": [
            {**entity, "version": entity["version"] + 1, "digest": "c" * 64}
            for entity in self.projection["entities"]
        ]}

    def test_identity_binding_rejects_cross_node_subsystem_and_kind(self):
        for change in ({"node": "B"}, {"subsystem": "detector"}, {"kind": "revocation"}):
            with self.subTest(change=change), self.assertRaises(ArchiveDenied):
                self.intent({**self.event, **change})
        self.assertEqual(self.archive.position(self.producer)["sequence"], 0)
        record = self.intent()
        self.assertEqual((record["producer"], record["node"], record["subsystem"]),
                         ("worker-A", "A", "worker"))
        self.assertEqual(record["event"]["actor"], "fixture-user")

    def test_rotation_intent_and_abort_do_not_claim_completed_mutation(self):
        pending = self.intent({**self.event, "authorization": "allow", "reason": "approved", "approval_id": "approval-1"})
        retained = self.archive.retrieve(self.investigator, "worker-A", "event-1")
        self.assertEqual(retained["lifecycle"], "PENDING")
        self.assertFalse(retained["mutation_committed"])
        self.archive.finalize(self.producer, pending["tag"], {
            **self.outcome, "basis": "verified_noncommit", "delivery": "withheld",
        })
        retained = self.archive.retrieve(self.investigator, "worker-A", "event-1")
        self.assertEqual(retained["lifecycle"], "ABORTED")
        self.assertFalse(retained["mutation_committed"])

    def test_rotation_requires_complete_composite_projection(self):
        event = {**self.event, "authorization": "allow", "reason": "approved", "approval_id": "approval-1"}
        partial = {"schema": 1, "entities": self.projection["entities"][1:]}
        with self.assertRaises(ValueError):
            self.archive.append_intent(self.producer, "operation-1", canonical(event),
                                       predecessor=GENESIS, deadline_ms=self.deadline, expected=partial)
        with self.assertRaises(ValueError):
            self.intent({**event, "approval_id": "unrelated-approval"})
        self.assertEqual(self.archive.position(self.producer)["sequence"], 0)
        pending = self.intent(event)
        valid = self.changed_projection()
        valid["entities"][0].update(version=0, digest=GENESIS)
        for projection in (
            partial,
            {"schema": 1, "entities": [self.projection["entities"][0], valid["entities"][1]]},
            {"schema": 1, "entities": [{**valid["entities"][0], "id": "other"}, valid["entities"][1]]},
        ):
            with self.assertRaises(ValueError):
                self.archive.finalize(self.producer, pending["tag"], {**self.outcome, "after": projection})
        final = self.archive.finalize(self.producer, pending["tag"], {**self.outcome, "after": valid})
        with self.assertRaises(ArchiveConflict):
            self.intent({**event, "event_id": "next"}, operation="next", predecessor=final["tag"])
        retained = self.archive.retrieve(self.investigator, "worker-A", "event-1")
        self.assertEqual(retained["lifecycle"], "CONFIRMED")
        self.assertTrue(retained["mutation_committed"])

    def test_initial_projection_is_authenticated(self):
        self.assertEqual(self.archive.position(self.producer)["initial_projection"], self.projection)
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("UPDATE initial SET body=?", (canonical(self.changed_projection()),))
        with self.assertRaises(ArchiveUnavailable):
            self.archive.position(self.producer)

    def test_reviewer_backward_rotation_is_rejected(self):
        event = {**self.event, "authorization": "allow", "reason": "approved",
                 "approval_id": "approval-1"}
        pending = self.intent(event)
        after = self.changed_projection()
        after["entities"][0].update(version=0, digest=GENESIS)
        for invalid_version in (1, 4):
            after["entities"][1]["version"] = invalid_version
            with self.subTest(version=invalid_version), self.assertRaises(ValueError):
                self.archive.finalize(self.producer, pending["tag"], {**self.outcome, "after": after})
        self.assertTrue(self.archive.position(self.producer)["has_pending"])

    def test_reviewer_unanchored_access_does_not_set_initial_state(self):
        raw = canonical({**self.event, "entity_id": "unanchored"})
        unknown = {"schema": 1, "entities": [
            {"kind": "asset", "id": "unanchored", "version": 1, "digest": "a" * 64},
        ]}
        with self.assertRaises(ArchiveConflict):
            self.archive.append_intent(self.producer, "other", raw, predecessor=GENESIS,
                                       deadline_ms=self.deadline, expected=unknown)
        self.assertEqual(self.archive.position(self.producer)["sequence"], 0)


    def test_producer_principal_cannot_be_shared_across_nodes(self):
        expiry = self.deadline
        grant = dict(principal="worker-A", role="producer", scopes=["rotation"],
                     expires_ms=expiry, revoked=False, node="A", subsystem="worker")
        other = Archive(self.directory / "other.sqlite", "other", **self.keys)
        with self.assertRaisesRegex(ValueError, "inconsistent bindings"):
            other.provision({self.producer: grant, self.investigator: {**grant, "node": "B"}},
                            initial=self.projection)
        self.assertFalse(other.path.exists())
        other.provision({self.producer: grant, self.investigator: {**grant, "principal": "worker-B", "node": "B"}},
                        initial=self.projection)
        pending = other.append_intent(self.producer, "op", canonical(self.event),
                                      predecessor=GENESIS, deadline_ms=expiry, expected=self.projection)
        state = other.position(self.investigator)
        self.assertTrue(state["has_pending"])
        self.assertIsNone(state["pending"])
        with self.assertRaises(ArchiveDenied):
            other.finalize(self.investigator, pending["tag"], self.outcome)

    def test_alert_requires_confirmed_producer_qualified_source(self):
        kinds = ["detector_source", "detector_alert"]
        grant = dict(principal="detector-A", role="producer", scopes=kinds,
                     expires_ms=self.deadline, revoked=False, node="A", subsystem="detector")
        detector = Archive(self.directory / "detector.sqlite", "detector", **self.keys)
        detector.provision({
            self.producer: grant,
            self.investigator: {k: v for k, v in {**grant, "role": "investigator"}.items()
                                if k not in {"node", "subsystem"}},
        }, initial=self.projection)
        empty = {"schema": 1, "entities": []}
        observed = {**self.event, "subsystem": "detector", "kind": "detector_source",
                    "authorization": "observed", "reason": "source_received",
                    "timing": {"corrected_ms": 1200, "uncertainty_ms": 125}}
        sources = [{"producer": "detector-A", "event_id": observed["event_id"]}]
        alert = {**observed, "kind": "detector_alert", "event_id": "alert-1",
                 "rule_id": "unusual_access", "rule_version": 1, "approval_ref": None,
                 "source_ids": sources}

        def append(op, event, previous):
            return detector.append_intent(self.producer, op, canonical(event), predecessor=previous,
                                          deadline_ms=self.deadline, expected=empty)

        with self.assertRaises(ArchiveConflict):
            append("alert", alert, GENESIS)
        source = append("source", observed, GENESIS)
        with self.assertRaises(ArchiveConflict):
            append("alert", alert, source["tag"])
        confirmed = detector.finalize(self.producer, source["tag"],
                                      {**self.outcome, "before": empty, "after": empty})
        for ids in ([{"producer": "other", "event_id": observed["event_id"]}], sources * 2):
            with self.assertRaises(ValueError):
                append("alert", {**alert, "source_ids": ids}, confirmed["tag"])
        append("alert", alert, confirmed["tag"])
        retained = detector.retrieve(self.investigator, "detector-A", observed["event_id"])
        self.assertEqual(retained["event_bytes"], canonical(observed))
        self.assertEqual(retained["lifecycle"], "CONFIRMED")

    def test_expired_producer_cannot_finalize_pending(self):
        pending = self.intent()
        with patch.object(Archive, "now", return_value=self.deadline):
            with self.assertRaises(ArchiveDenied):
                self.archive.finalize(self.producer, pending["tag"], self.outcome)
        self.assertEqual(self.archive.position(self.producer)["pending"], pending)

    def test_explicit_creation_unknown_denial_and_revocation_noop(self):
        archive = Archive(self.directory / "transitions.sqlite", "transitions", **self.keys)
        archive.provision({self.producer: dict(
            principal="worker-A", role="producer", node="A", subsystem="worker",
            scopes=["enrolment", "resource_create", "access_decision", "revocation"],
            expires_ms=self.deadline, revoked=False,
        )}, initial=self.projection)
        head = GENESIS

        def operation(name, kind, entity_id, authorization, reason, before, after):
            nonlocal head
            event = {**self.event, "event_id": name, "kind": kind, "entity_id": entity_id,
                     "authorization": authorization, "reason": reason}
            pending = archive.append_intent(self.producer, name, canonical(event), predecessor=head,
                                            deadline_ms=self.deadline, expected=before)
            final = archive.finalize(self.producer, pending["tag"], {
                **self.outcome, "before": before, "after": after,
            })
            head = final["tag"]
            return final

        empty = {"schema": 1, "entities": []}
        operation("denial", "access_decision", "absent", "deny", "unknown_resource", empty, empty)

        def projection(kind, entity_id, version, **metadata):
            return {"schema": 1, "entities": [
                {"kind": kind, "id": entity_id, "version": version,
                 "digest": str(version) * 64, **metadata},
            ]}

        operation("create", "resource_create", "new", "allow", "authorized",
                  projection("asset", "new", 0), projection("asset", "new", 1))
        absent = projection("credential", "device", 0, status="absent")
        active = projection("credential", "device", 1, status="active")
        revoked = projection("credential", "device", 2, status="revoked")
        operation("enrol", "enrolment", "device", "allow", "authorized", absent, active)
        operation("revoke", "revocation", "device", "allow", "revoked", active, revoked)
        final = operation("noop", "revocation", "device", "allow", "already_revoked", revoked, revoked)
        self.assertEqual(final["outcome"]["before"], final["outcome"]["after"])
