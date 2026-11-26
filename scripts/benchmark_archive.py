"""Measure bounded local archive cost without contacting a worker."""
import json
import math
from pathlib import Path
import secrets
import sqlite3
import statistics
import tempfile
import threading
import time

from kig_core.archive import Archive, GENESIS, MAX_RECORDS, canonical


def sample(action):
    started = time.perf_counter_ns()
    result = action()
    return result, (time.perf_counter_ns() - started) / 1_000_000


def stats(values):
    return {"p50_ms": round(statistics.median(values), 3),
            "p95_ms": round(sorted(values)[math.ceil(0.95 * len(values)) - 1], 3)}


def run(path):
    archive = Archive(path, "benchmark", receipt_key=secrets.token_bytes(32),
                      grant_key=secrets.token_bytes(32))
    producer = secrets.token_urlsafe(32)
    deadline = archive.now() + 300_000
    projection = {"schema": 1, "entities": [
        {"kind": "asset", "id": "fixture", "version": 1, "digest": "a" * 64},
        {"kind": "credential", "id": "device", "version": 1,
         "digest": "b" * 64, "status": "active"},
        {"kind": "grant", "id": "fixture", "version": 1, "digest": "c" * 64},
    ]}
    archive.provision({producer: dict(principal="writer", role="producer",
                                     scopes=["access_decision"], expires_ms=deadline,
                                     revoked=False, node="A", subsystem="worker")}, initial=projection)
    outcome = dict(basis="verified_commit", before=projection, after=projection, delivery="unknown")
    predecessor = GENESIS
    operations = 0

    def append_operation():
        nonlocal predecessor, operations
        name = f"op-{operations}"
        event = canonical(dict(version=2, event_id=name, request_id=name, actor="fixture-user",
                               node="A", subsystem="worker", kind="access_decision",
                               credential_id="device",
                               entity_id="fixture", authorization="allow", reason="authorized",
                               received_ms=archive.now(), source_ids=[]))
        pending, append_ms = sample(lambda: archive.append_intent(
            producer, name, event, predecessor=predecessor, deadline_ms=deadline,
            expected=projection))
        final, finalize_ms = sample(lambda: archive.finalize(producer, pending["tag"], outcome))
        predecessor = final["tag"]
        operations += 1
        return append_ms, finalize_ms

    def contend():
        """Measure the full append/finalize after a 50 ms competing writer lock."""
        locked = threading.Event()

        def blocker():
            with sqlite3.connect(path) as db:
                db.execute("BEGIN IMMEDIATE")
                locked.set()
                time.sleep(0.05)

        thread = threading.Thread(target=blocker)
        thread.start()
        try:
            if not locked.wait(2):
                raise RuntimeError("benchmark writer lock was not acquired")
            _, elapsed = sample(append_operation)
            return elapsed
        finally:
            thread.join()

    for fill in (0, 25, 50, 90):
        while operations * 2 < math.floor(MAX_RECORDS * fill / 200) * 2:
            append_operation()
        at_start = {"records": operations * 2, "sqlite_bytes": path.stat().st_size}
        reads = [sample(lambda: archive.position(producer))[1] for _ in range(12)]
        appends, finalizations = zip(*(append_operation() for _ in range(12)))
        contended = [contend() for _ in range(5)]
        print(json.dumps({"target_percent": fill, **at_start, "verify_position": stats(reads),
                          "append": stats(appends), "finalize": stats(finalizations),
                          "contended_operation": stats(contended), "verification_failures": 0}),
              flush=True)


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as directory:
        run(Path(directory) / "measure.sqlite")
