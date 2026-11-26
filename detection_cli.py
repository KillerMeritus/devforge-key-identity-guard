"""Inspect organizer practice findings and benchmark mixed synthetic sessions."""
import argparse
import csv
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import statistics
import time

from kig_core.detector import Detector, analyze, timestamp


def synthetic(repetitions=12):
    """Construct labelled episodes independently of detector outputs."""
    base = datetime(2026, 1, 15, 9, tzinfo=timezone.utc)
    for index in range(repetitions):
        prefix = f"session-{index}"
        events, expected = [], set()

        def at(seconds):
            return (base + timedelta(seconds=seconds)).isoformat()

        def event(name, when, receipt, *, actor="reader", action="read", role="viewer",
                  source="portal", target="catalog", outcome="allow", approval="", offset=0,
                  expected_rule=None):
            event_id = f"{prefix}-{name}"
            events.append(dict(event_id=event_id, event_time_utc=at(when + offset / 1000),
                               received_time_utc=at(receipt), source_clock_offset_ms=offset,
                               actor=f"{prefix}-{actor}", source_service=source, target_service=target,
                               action=action, role_after=role, outcome=outcome, approval_id=approval,
                               session_id=f"{prefix}-{actor}", correlation_id=prefix))
            if expected_rule:
                expected.add((event_id, expected_rule))

        approval = dict(approval_id="approved", subject=f"{prefix}-reader", operation="grant_role",
                        role="report-reader", scope=["reports"], valid_from_utc=at(0),
                        valid_until_utc=at(2))
        event("routine", 0, 0.1)
        event("grant", 0.1, 0.2, action="role_change", role="report-reader",
              source="admin-console", target="identity", outcome="success", approval="approved")
        event("scoped-read", 1, 1.2, role="report-reader", target="reports",
              approval="approved", offset=2000)
        event("expired-read", 2, 2.1, role="report-reader", target="reports",
              approval="approved", expected_rule="access_outside_approval")
        event("unexpected-grant", 2.2, 3.0, actor="other", action="role_change", role="operator",
              source="admin-console", target="identity", outcome="success",
              expected_rule="unexpected_role_change")
        event("follow-up", 2.6, 2.8, actor="other", role="operator", target="reports",
              expected_rule="review_after_role_change")
        event("isolated-denial", 3, 3.1, actor="visitor", target="billing", outcome="deny")
        event("worker-normal", 3.1, 3.2, actor="worker", role="service-reader", source="reports")
        event("worker-hop-1", 3.2, 3.5, actor="worker", role="service-reader", source="reports",
              target="billing", outcome="deny", expected_rule="lateral_movement_candidate")
        event("worker-hop-2", 3.3, 3.4, actor="worker", role="service-reader", source="billing",
              target="archive", outcome="deny", expected_rule="lateral_movement_candidate")
        yield sorted(events, key=lambda item: item["received_time_utc"]), [approval], expected


def benchmark(*, real_time=False):
    tp = fp = fn = benign = benign_alerts = total = 0
    latencies = []
    rule_counts = {}
    # Compress fixture receipt intervals for a quick, repeatable local replay.
    scale = 1 if real_time else 0.01
    for events, approvals, expected in synthetic():
        detector = Detector(approvals)
        alerts = []
        first = timestamp(events[0]["received_time_utc"])
        start = time.perf_counter()
        for event in events:
            deadline = start + (timestamp(event["received_time_utc"]) - first) * scale
            remaining = deadline - time.perf_counter()
            if remaining > 0:
                time.sleep(remaining)
            emitted, _ = detector.ingest(event, received_at=time.perf_counter())
            alerts.extend(emitted)
        alerts.extend(detector.finish())
        detected = {(alert["anchor_event_id"], alert["rule"]) for alert in alerts}
        matched = detected & expected
        tp += len(matched)
        fp += len(detected - expected)
        fn += len(expected - detected)
        total += len(events)
        positive_events = {anchor for anchor, _ in expected}
        benign += len(events) - len(positive_events)
        benign_alerts += sum(anchor not in positive_events for anchor, _ in detected)
        for alert in alerts:
            if (alert["anchor_event_id"], alert["rule"]) in matched:
                rule_counts[alert["rule"]] = rule_counts.get(alert["rule"], 0) + 1
                latencies.append(alert["latency_ms"])

    latencies.sort()
    return dict(events=total, positives=tp + fn, true_positives=tp, false_positives=fp,
                false_negatives=fn, precision=tp / (tp + fp) if tp + fp else 0,
                recall=tp / (tp + fn), f1=2 * tp / (2 * tp + fp + fn),
                false_alerts_per_1000_benign=1000 * benign_alerts / benign, matched_by_rule=rule_counts,
                latency_samples=len(latencies), median_ms=statistics.median(latencies) if latencies else None,
                p95_ms=latencies[(95 * len(latencies) - 1) // 100] if latencies else None,
                receipt_time_scale=scale, latency_scope="local receipt-to-alert evaluation; no external transport")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--practice", type=Path)
    parser.add_argument("--real-time", action="store_true", help="Preserve fixture receipt intervals")
    args = parser.parse_args()
    report = {"benchmark": benchmark(real_time=args.real_time)}
    if args.practice:
        with (args.practice / "events.csv").open() as handle:
            events = list(csv.DictReader(handle))
        approvals = json.loads((args.practice / "approvals.json").read_text())["changes"]
        alerts, notes = analyze(events, approvals)
        report["practice"] = {"alerts": alerts, "timing_notes": notes}
    print(json.dumps(report, indent=2))
