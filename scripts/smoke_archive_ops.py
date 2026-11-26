"""Smoke-test the archive CLI against a disposable two-worker fixture."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, closing
import json
from pathlib import Path
import secrets
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time

from demo_cli import call, start, wait_for
from kig_core.guard import Guard
from kig_core.witness import RevocationWitness


def main():
    with tempfile.TemporaryDirectory(prefix="devforge-ops-verification-") as directory:
        state = Path(directory)
        keys = [secrets.token_bytes(32) for _ in range(3)]
        for name, key in zip(("audit", "storage", "backup"), keys):
            (state / f"{name}.key").write_bytes(key)
        witness_path = state / "witness" / "checkpoint.sqlite"
        witness_path.parent.mkdir()
        witness = RevocationWitness(witness_path, keys[0])
        witness.provision()
        guard = Guard(state / "demo.sqlite", *keys, witness=witness)
        operator = guard.enroll("operator", "admin")
        guard.seed_file("brief", b"synthetic", "operator")
        approval = guard.approve_rotation("operator", "brief", 1, time.time() + 120)

        def ops(*arguments):
            result = subprocess.run([sys.executable, "archive_ops.py", "--state", str(state),
                                     *map(str, arguments)], check=True, capture_output=True, text=True)
            return json.loads(result.stdout)

        investigator = state / "investigator.credential"
        assert ops("provision", investigator)["status"] == "archive_provisioned"
        assert stat.S_IMODE(investigator.stat().st_mode) == 0o600
        assert ops("status")["pending"] is None
        fields = {"target": "brief", "version": 1, "approval": approval}
        with ExitStack() as stack:
            log = state / "worker-a.log"
            port, node = start(stack, state, "A", log, archive=True, checkpoint="committed")
            pool = stack.enter_context(ThreadPoolExecutor(max_workers=1))
            pending_request = pool.submit(call, port, "rotate", operator, fields, idempotency_key="cli-check")
            try:
                wait_for(lambda: "CHECKPOINT prepared" in log.read_text().splitlines(), "preparation")
                (state / "resume-rotation").touch()
                wait_for(lambda: "CHECKPOINT committed" in log.read_text().splitlines(), "working commit")
            finally:
                node.kill()
                assert node.wait(timeout=5) == -signal.SIGKILL
            try:
                pending_request.result()
            except OSError:
                pass
            else:
                raise AssertionError("Unexpected rotation reply")

        tag = ops("status")["pending"]
        assert tag
        recovery = state / "recovery.credential"
        producers = [state / "archive" / f"producer-{node}" for node in ("A", "B")]
        for producer in producers:
            producer.rename(producer.with_suffix(".offline"))
        assert ops("authorize-recovery", tag, "cli-recovery", recovery)["status"] == "recovery_authorized"
        assert stat.S_IMODE(recovery.stat().st_mode) == 0o600
        receipt = ops("recover", tag, recovery)
        assert receipt["state"] == "CONFIRMED" and receipt["recovery_actor"] == "cli-recovery"
        assert receipt["producer"] == "worker-A" and ops("status")["pending"] is None
        for producer in producers:
            producer.with_suffix(".offline").rename(producer)
        snapshot = state / "snapshot.sqlite"
        with closing(sqlite3.connect(guard.path)) as live, closing(sqlite3.connect(snapshot)) as saved:
            live.backup(saved)
        assert ops("restore", snapshot)["status"] == "verified_snapshot_restored"
        with ExitStack() as stack:
            port, _ = start(stack, state, "B", state / "worker-b.log", archive=True)
            status, result, _ = call(port, "rotate", operator, fields, idempotency_key="cli-check")
            assert status == 200 and result["version"] == 2
        print("PASS offline provision, scoped authorization, recovery without producer credentials, verified restore, and retry")


if __name__ == "__main__":
    main()
