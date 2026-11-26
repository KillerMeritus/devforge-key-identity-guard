"""Inspect practice findings and benchmark a separately generated labelled corpus."""
import argparse
import csv
import json
from pathlib import Path
import statistics

from kig_core.detector import analyze


def synthetic():
    events, positives = [], set()
    for index in range(480):
        suspicious = index % 12 == 0
        event_id = f"sample-{index}"
        if suspicious:
            positives.add(event_id)
        events.append(dict(event_id=event_id, event_time_utc="2026-01-15T09:00:00Z",
                           received_time_utc="2026-01-15T09:00:00.200Z",
                           source_clock_offset_ms=0, actor=f"fixture-{index}",
                           source_service="admin-console" if suspicious else "portal",
                           target_service="identity" if suspicious else "catalog",
                           action="role_change" if suspicious else "read", role_after="viewer",
                           outcome="success" if suspicious else "allow", approval_id="",
                           session_id=event_id, correlation_id=event_id))
    return events, positives


def benchmark():
    events, expected = synthetic()
    alerts, _ = analyze(events, [])
    detected = {alert["anchor_event_id"] for alert in alerts}
    tp, fp, fn = len(expected & detected), len(detected - expected), len(expected - detected)
    latencies = sorted(alert["latency_ms"] for alert in alerts
                       if alert["anchor_event_id"] in expected)
    return dict(events=len(events), positives=len(expected), true_positives=tp,
                false_positives=fp, false_negatives=fn, f1=2 * tp / (2 * tp + fp + fn),
                false_alerts_per_1000_benign=1000 * fp / (len(events) - len(expected)),
                median_ms=statistics.median(latencies), p95_ms=latencies[(95 * len(latencies) - 1)//100],
                latency_scope="local batch rule evaluation on synthetic fixtures")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--practice", type=Path)
    args = parser.parse_args()
    report = {"benchmark": benchmark()}
    if args.practice:
        with (args.practice / "events.csv").open() as handle:
            events = list(csv.DictReader(handle))
        approvals = json.loads((args.practice / "approvals.json").read_text())["changes"]
        alerts, notes = analyze(events, approvals)
        report["practice"] = {"alerts": alerts, "timing_notes": notes}
    print(json.dumps(report, indent=2))
