"""Retain the existing detector's inputs and findings in a local evidence archive."""

import hashlib
import os
import secrets
import statistics
import time

from .archive import Archive, ArchiveConflict, canonical
from .detector import UNCERTAINTY_SECONDS, analyze, approved, corrected, timestamp
from .worker_archive import private_write

PRODUCER = "replay-detector"
KINDS = ("detector_source", "detector_alert")



def evidence_archive(directory):
    receipt_key, grant_key = secrets.token_bytes(32), secrets.token_bytes(32)
    archive = Archive(directory / "detector.sqlite", "detector-evidence",
                      receipt_key=receipt_key, grant_key=grant_key)
    writer, investigator = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    grants = dict(scopes=list(KINDS), expires_ms=archive.now() + 3_600_000, revoked=False)
    archive.provision(
        {writer: {**grants, "role": "producer", "principal": PRODUCER,
                  "node": "replay", "subsystem": "detector"},
         investigator: {**grants, "role": "investigator", "principal": "replay-reviewer"}},
        initial={"schema": 1, "entities": [{"kind": "audit_anchor", "id": "detector", "version": 1,
                                          "digest": hashlib.sha256(b"detector-replay-v1").hexdigest()}]},
    )
    for name, value in (("receipt.key", receipt_key), ("grant.key", grant_key),
                        ("producer.token", writer.encode()), ("investigator.token", investigator.encode())):
        private_write(directory / name, value)
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return archive, writer, investigator


def open_evidence_archive(directory):
    archive = Archive(directory / "detector.sqlite", "detector-evidence",
                      receipt_key=(directory / "receipt.key").read_bytes(),
                      grant_key=(directory / "grant.key").read_bytes())
    return archive, (directory / "producer.token").read_text(), (directory / "investigator.token").read_text()


def envelope(event_id, actor, kind, reason, received_ms, corrected_ms):
    return dict(version=2, event_id=event_id, request_id=event_id, actor=actor, node="replay",
                subsystem="detector", kind=kind, entity_id=event_id, authorization="observed",
                reason=reason, received_ms=received_ms, source_ids=[],
                timing={"corrected_ms": corrected_ms,
                        "uncertainty_ms": round(UNCERTAINTY_SECONDS * 1000)})


def source_event(event):
    received = round(timestamp(event["received_time_utc"]) * 1000)
    corrected_ms = round(corrected(event) * 1000)
    return {
        **envelope(event["event_id"], event["actor"], "detector_source", "source_observation",
                   received, corrected_ms),
        "detector_context": dict(
            event_ms=round(timestamp(event["event_time_utc"]) * 1000), received_ms=received,
            event_time_utc=event["event_time_utc"], received_time_utc=event["received_time_utc"],
            clock_offset_ms=int(event["source_clock_offset_ms"]), action=event["action"],
            outcome=event["outcome"], role=event["role_after"], role_before=event.get("role_before"),
            source_service=event["source_service"],
            target_service=event["target_service"], session_id=event["session_id"],
            correlation_id=event["correlation_id"], approval_id=event["approval_id"] or None,
            requested_scope=sorted(set(event.get("requested_scope", ()))),
        ),
    }


def approval_context(event, approvals):
    rule = approvals.get(event["approval_id"])
    if rule is None:
        return "missing", None, None
    snapshot = {key: rule[key] for key in ("approval_id", "subject", "operation", "role",
                                          "valid_from_utc", "valid_until_utc")}
    snapshot["scope"] = sorted(set(rule.get("scope", ())))
    proof = hashlib.sha256(canonical(snapshot)).hexdigest()
    if not approved(event, approvals):
        return "mismatch", proof, snapshot
    if event["action"] == "read" and event["target_service"] not in rule.get("scope", ()):
        return "outside_scope", proof, snapshot
    return "matches", proof, snapshot


def replay(archive, writer, investigator, events, approvals):
    """Evaluate a finite input in arrival order after retaining each source."""
    unique = {}
    for event in events:
        eid = event["event_id"]
        if eid in unique and unique[eid] != event:
            raise ArchiveConflict("conflicting detector input")
        unique.setdefault(eid, event)
    approvals = tuple(approvals)
    retained, source_receipts = {}, {}
    ingestion_ms = []
    for eid, event in unique.items():
        source = source_event(event)
        start = time.perf_counter()
        receipt = archive.record_telemetry(writer, canonical(source))
        source_receipts[eid] = {"state": receipt["state"], "producer": receipt["producer"],
                                "sequence": receipt["sequence"], "tag": receipt["tag"]}
        ingestion_ms.append((time.perf_counter() - start) * 1000)
        retained[eid] = source

    alerts, notes = analyze(unique.values(), approvals)
    approvals = {item["approval_id"]: item for item in approvals}
    findings = []
    for alert in alerts:
        anchor, rule = alert["anchor_event_id"], alert["rule"]
        version = alert["rule_version"]
        classification = alert["classification"]
        explanation = alert["explanation"]
        source = retained[anchor]
        evidence = [retained[eid] for eid in alert["evidence_event_ids"]]
        approval, proof, snapshot = approval_context(unique[anchor], approvals)
        event_id = f"alert-{hashlib.sha256(canonical([anchor, rule, version])).hexdigest()}"
        derived = {
            **envelope(event_id, source["actor"], "detector_alert", rule,
                       max(item["received_ms"] for item in evidence), source["timing"]["corrected_ms"]),
            "source_ids": [{"producer": PRODUCER, "event_id": item["event_id"]} for item in evidence],
            "rule_id": rule, "rule_version": version, "approval_ref": unique[anchor]["approval_id"] or None,
            "detector_context": {
                "classification": classification,
                "approval_status": approval, "approval_digest": proof, "approval": snapshot,
            },
        }
        archive.record_telemetry(writer, canonical(derived))
        receipt = archive.retrieve(investigator, PRODUCER, event_id)
        if receipt["lifecycle"] != "CONFIRMED" or receipt["event_bytes"] != canonical(derived):
            raise ArchiveConflict("detector alert receipt did not verify")
        findings.append({"event": derived, "receipt": receipt["terminal_receipt"],
                         "anchor_event_id": anchor, "services": alert["services"],
                         "service_edges": [list(edge) for edge in alert["service_edges"]],
                         "explanation": explanation, "uncertainty_ms": alert["uncertainty_ms"]})
    ingestion_ms.sort()
    return {
        "findings": findings, "timing_notes": notes, "sources": list(retained.values()),
        "source_receipts": source_receipts,
        "source_ingestion": {"samples": len(ingestion_ms),
                             "median_ms": round(statistics.median(ingestion_ms), 3) if ingestion_ms else None,
                             "p95_ms": round(ingestion_ms[(95 * len(ingestion_ms) - 1) // 100], 3)
                             if ingestion_ms else None},
    }
