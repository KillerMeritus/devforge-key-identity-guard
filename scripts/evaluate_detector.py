"""Score the fixed held-out data and optionally load a prior detector revision."""
import argparse
import json
import math
from pathlib import Path
import statistics
import subprocess
import types

from kig_core import detector


ROOT = Path(__file__).resolve().parents[1]


def load_baseline(revision):
    commit = subprocess.check_output(
        ["git", "rev-parse", "--verify", revision + "^{commit}"], cwd=ROOT, text=True,
    ).strip()
    source = subprocess.check_output(["git", "show", commit + ":kig_core/detector.py"], cwd=ROOT, text=True)
    baseline = types.ModuleType("heldout_baseline")
    exec(compile(source, commit + ":kig_core/detector.py", "exec"), baseline.__dict__)
    return baseline


def evaluate(module, fixture):
    events, approvals = fixture["events"], fixture["approvals"]
    alerts, notes = module.analyze(events, approvals)
    expected = {(item["event_id"], item["rule"]) for item in fixture["expected"]}
    observed = {(item["anchor_event_id"], item["rule"]) for item in alerts}
    matched, false, missed = expected & observed, observed - expected, expected - observed
    latencies = sorted(item["latency_ms"] for item in alerts
                       if (item["anchor_event_id"], item["rule"]) in matched)
    benign = len(fixture["benign_event_ids"])
    tp, fp, fn = len(matched), len(false), len(missed)
    ratio = lambda n, d: n / d if d else None
    corrected_offsets = [int(event["source_clock_offset_ms"]) for event in events]
    arrival_deltas = [round(1000 * (module.timestamp(e["received_time_utc"]) - module.corrected(e)))
                      for e in events]
    return {
        "events": len(events), "unique_event_ids": len({item["event_id"] for item in events}),
        "benign_events": benign, "contested_ids": len(fixture["contested_event_ids"]),
        "true_positives": tp, "false_positives": fp, "false_negatives": fn,
        "precision": ratio(tp, tp + fp), "recall": ratio(tp, tp + fn),
        "f1": ratio(2 * tp, 2 * tp + fp + fn), "false_alerts_per_1000_benign": ratio(1000 * fp, benign),
        "latency_samples": len(latencies), "median_alert_ms": statistics.median(latencies) if latencies else None,
        "p95_alert_ms": latencies[math.ceil(.95 * len(latencies)) - 1] if latencies else None,
        "source_offset_range_ms": [min(corrected_offsets), max(corrected_offsets)],
        "receipt_minus_corrected_range_ms": [min(arrival_deltas), max(arrival_deltas)],
        "configured_lateness_seconds": module.LATENESS_SECONDS,
        "per_event_uncertainty_ms": module.UNCERTAINTY_SECONDS * 1000,
        "false_alert_keys": sorted(false), "missed_alert_keys": sorted(missed), "notes": notes,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline")
    parser.add_argument("--expanded", action="store_true", help="evaluate the separate expanded cohort")
    args = parser.parse_args()
    if args.expanded:
        from scripts.expanded_detector_fixture import generate

        fixture = generate()
    else:
        fixture = json.loads((ROOT / "tests/fixtures/detector-heldout.json").read_text())
    result = {"candidate": evaluate(detector, fixture)}
    if args.baseline:
        result["baseline"] = evaluate(load_baseline(args.baseline), fixture)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
