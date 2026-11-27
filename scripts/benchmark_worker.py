"""Measure same-host worker operations with independent audit and transport controls."""
import argparse
from contextlib import ExitStack
import json
import math
from pathlib import Path
import secrets
import statistics
import tempfile
import time

from demo_cli import call, start
from kig_core.guard import Guard
from kig_core.witness import RevocationWitness
from kig_core.worker_archive import ArchivedGuard, provision_archive, store_lock


def measure(operation, samples):
    elapsed = []
    for _ in range(samples):
        start_ns = time.perf_counter_ns()
        operation()
        elapsed.append((time.perf_counter_ns() - start_ns) / 1_000_000)
    return {"samples": samples, "p50_ms": round(statistics.median(elapsed), 3),
            "p95_ms": round(sorted(elapsed)[math.ceil(samples * 0.95) - 1], 3)}


def run(archive, history_sizes, samples):
    with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
        state = Path(directory)
        keys = [secrets.token_bytes(32) for _ in range(3)]
        for label, key in zip(("audit", "storage", "backup"), keys):
            (state / f"{label}.key").write_bytes(key)
        witness_file = state / "witness" / "checkpoint.sqlite"
        witness_file.parent.mkdir()
        witness = RevocationWitness(witness_file, keys[0])
        witness.provision()
        guard = Guard(state / "demo.sqlite", *keys, witness=witness)
        admin = guard.enroll("admin", "admin")
        reader = guard.enroll("reader")
        guard.seed_file("bench", b"fixture" * 256, "reader")
        if archive:
            provision_archive(state, guard)
            coordinator = ArchivedGuard(guard, state)
        port, _ = start(stack, state, "A", state / "worker.log", archive=archive)

        def read():
            status, payload, _ = call(port, "read", reader, {"target": "bench", "version": 1})
            if status != 200 or payload["reason"] != "read":
                raise RuntimeError(f"protected read failed with HTTP {status}")

        def health():
            if call(port, "health")[0] != 200:
                raise RuntimeError("worker health failed")

        def verified():
            if archive:
                with store_lock(coordinator.directory), guard.transaction(write=False, archive=True) as db:
                    with coordinator.archive.verified(write=False) as (_, records, _, initial):
                        coordinator.verify(db, records, initial)
            else:
                guard.evidence(admin)

        count = 0
        for size in history_sizes:
            while count < size:
                read()
                count += 1
            row = {
                "mode": "archive" if archive else "baseline",
                "working_audit_at_start": count,
                "archive_records_at_start": 2 * count if archive else 0,
                "loopback_health_round_trip": measure(health, samples),
                "local_read_only_verification": measure(verified, samples),
                "http_protected_read": measure(read, samples),
            }
            print(json.dumps(row), flush=True)
            count += samples


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=12)
    parser.add_argument("--history", type=int, nargs="+", default=[16, 80, 200, 400])
    args = parser.parse_args()
    if not 1 <= args.samples <= 20 or not 0 <= min(args.history) <= max(args.history) <= 480:
        parser.error("use 1–20 samples and history sizes between 0 and 480")
    if any(b - a < args.samples for a, b in zip(args.history, args.history[1:])):
        parser.error("history sizes must increase by at least the sample count")
    for archive in (False, True):
        run(archive, args.history, args.samples)
