"""Measure the rubric properties on isolated loopback and SQLite fixtures."""
import argparse
from contextlib import ExitStack
import csv
import json
import math
import os
from pathlib import Path
import platform
import secrets
import statistics
import tempfile
import time

from console_scenarios import time_machine
from demo_cli import call, require, run, start
from kig_core.detector import analyze
from kig_core.detector_archive import evidence_archive, replay
from kig_core.guard import Guard
from kig_core.witness import RevocationWitness
from kig_core.worker_archive import ArchivedGuard, provision_archive


def summary(values):
    values = sorted(values)
    return {"n": len(values), "median_ms": round(statistics.median(values), 4),
            "p95_ms": round(values[math.ceil(.95 * len(values)) - 1], 4),
            "min_ms": round(values[0], 4), "max_ms": round(values[-1], 4)}


def elapsed(callable_, *args, **kwargs):
    start_ns = time.perf_counter_ns()
    result = callable_(*args, **kwargs)
    return (time.perf_counter_ns() - start_ns) / 1_000_000, result


def loopback_reads(archive_mode, probes):
    with tempfile.TemporaryDirectory(prefix="devforge-measure-") as directory, ExitStack() as stack:
        state = Path(directory)
        keys = [secrets.token_bytes(32) for _ in range(3)]
        for name, key in zip(("audit", "storage", "backup"), keys):
            (state / f"{name}.key").write_bytes(key)
        (state / "witness").mkdir()
        witness = RevocationWitness(state / "witness" / "checkpoint.sqlite", keys[0])
        witness.provision()
        guard = Guard(state / "demo.sqlite", *keys, witness=witness)
        token = guard.enroll("reader")
        guard.seed_file("brief", b"x" * 1024, "reader")
        if archive_mode:
            provision_archive(state, guard)
        port, _ = start(stack, state, "A", state / "worker.log", archive=archive_mode)
        fields = {"target": "brief", "version": 1}
        samples = []
        for _ in range(probes):
            delay, (status, _, _) = elapsed(call, port, "read", token, fields)
            require(status == 200, "latency probe did not read the fixture")
            samples.append(delay)
        result = {"http_read": summary(samples)}
        if archive_mode:
            coordinator = ArchivedGuard(guard, state, "A")

            def verification():
                with guard.transaction(write=False, archive=True) as db:
                    with coordinator.archive.verified(write=False) as (_, records, _, initial):
                        coordinator.verify(db, records, initial)
                return len(records)

            verified = [elapsed(verification) for _ in range(probes)]
            result["archive_verification"] = summary([sample for sample, _ in verified])
            result["verified_receipt_rows"] = verified[-1][1]
        return result


def detector_overhead(practice, repetitions):
    with (practice / "events.csv").open() as source:
        events = list(csv.DictReader(source))
    approvals = json.loads((practice / "approvals.json").read_text())["changes"]
    local, archived, ingestion = [], [], []
    for _ in range(repetitions):
        delay, _ = elapsed(analyze, events, approvals)
        local.append(delay)
        with tempfile.TemporaryDirectory(prefix="devforge-detection-measure-") as directory:
            config = evidence_archive(Path(directory))
            delay, result = elapsed(replay, *config, events, approvals)
        archived.append(delay)
        ingestion.append(result["source_ingestion"])
    return {"events": len(events), "confirmed_findings": len(result["findings"]),
            "detector_only": summary(local), "archived_replay": summary(archived),
            "single_replay_source_ingestion": ingestion[0],
            "median_difference_ms": round(statistics.median(archived) - statistics.median(local), 4)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--practice", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=4)
    parser.add_argument("--probes", type=int, default=40)
    args = parser.parse_args()
    if not 1 <= args.runs <= 12 or not 1 <= args.probes <= 100:
        parser.error("runs must be 1–12 and probes 1–100")
    measured = {}
    for phase in ("pre", "post"):
        runs = [run(phase) for _ in range(args.runs)]
        measured[phase] = [{key: item[key] for key in ("active_version", "revocation_ms", "last_denial_ms",
                                                        "recovery_ms", "continuity", "nodes", "cutoff")}
                           for item in runs]
    snapshots = [time_machine() for _ in range(args.runs)]
    report = {
        "environment": {"system": platform.system(), "release": platform.release(),
                        "python": platform.python_version(), "architecture": platform.machine(),
                        "cpu_count_visible": os.cpu_count(), "timers": "same-host monotonic and perf_counter_ns"},
        "configured_grace_window_ms": 0, "crash_scenarios": measured,
        "experimental_snapshot_restore": summary([item["recovery_ms"] for item in snapshots]),
        "fixture_bytes": 1024, "baseline": loopback_reads(False, args.probes),
        "archive": loopback_reads(True, args.probes),
        "detector_overhead": detector_overhead(args.practice, args.runs),
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
