"""Explainable detection for the organizer's synthetic event schema."""
from collections import defaultdict
from datetime import datetime
import time


LATENESS_SECONDS = 5
UNCERTAINTY_SECONDS = 0.125
ROLE_TARGETS = {
    "viewer": {"catalog"},
    "report-reader": {"catalog", "reports", "reports-node-a", "reports-node-b"},
    "operator": {"catalog", "identity"},
}
SERVICE_EDGES = {"service-reader": {("reports", "catalog")}}


def timestamp(value):
    return datetime.fromisoformat(value).timestamp()


def corrected(event):
    return timestamp(event["event_time_utc"]) - int(event["source_clock_offset_ms"]) / 1000


def approved(event, changes):
    approval = changes.get(event["approval_id"])
    if not approval:
        return False
    return (
        approval["subject"] == event["actor"]
        and approval["operation"] == "grant_role"
        and approval["role"] == event["role_after"]
        and set(event.get("requested_scope", ())).issubset(approval.get("scope", ()))
        and timestamp(approval["valid_from_utc"]) <= corrected(event)
        < timestamp(approval["valid_until_utc"])
    )


def analyze(events, approvals):
    changes = {item["approval_id"]: item for item in approvals}
    groups = defaultdict(list)
    notes, alerts, unexpected = [], {}, {}
    arrival = {}
    for event in events:
        event_id = event["event_id"]
        started = time.perf_counter()
        arrival[event_id] = started
        effective = corrected(event)
        late = abs(timestamp(event["received_time_utc"]) - effective) > LATENESS_SECONDS
        if late:
            notes.append({"event": event_id, "reason": "arrival_outside_window"})
        if event["action"] == "role_change" and event["outcome"] == "success":
            if not approved(event, changes):
                unexpected[event_id] = event
                add_alert(alerts, event, "unexpected_role_change", [event], started)
        groups[event["actor"], event["session_id"]].append((effective, event, late))

    for group in groups.values():
        group.sort(key=lambda item: item[0])
        prior = None
        paths = defaultdict(list)
        for when, event, late in group:
            event_id = event["event_id"]
            if late:
                continue
            if event_id in unexpected:
                prior = (when, event)
            if event["action"] not in {"read", "list_roles"}:
                continue
            target = event["target_service"]
            edge = (event["source_service"], target)
            role = event["role_after"]
            if prior and event["outcome"] == "allow":
                if when - prior[0] <= 2 * UNCERTAINTY_SECONDS:
                    notes.append({"event": event_id, "reason": "order_uncertain"})
                else:
                    add_alert(alerts, event, "review_after_role_change", [prior[1], event],
                              max(arrival[event_id], arrival[prior[1]["event_id"]]))
            if role in SERVICE_EDGES and edge not in SERVICE_EDGES[role]:
                paths[event["correlation_id"]].append(event)
            approval = changes.get(event["approval_id"])
            if (event["outcome"] == "allow" and approval
                    and approval["operation"] == "grant_role"
                    and target != "catalog"
                    and (not approved(event, changes) or target not in approval.get("scope", ()))):
                add_alert(alerts, event, "access_outside_approval", [event], arrival[event_id])
            if (event["outcome"] == "allow" and role in ROLE_TARGETS
                    and target not in ROLE_TARGETS[role] and event_id not in alerts):
                add_alert(alerts, event, "unexpected_allowed_access", [event], arrival[event_id])
        for path in paths.values():
            if len({(item["source_service"], item["target_service"]) for item in path}) < 2:
                continue
            for event in path:
                add_alert(alerts, event, "lateral_movement_candidate", path,
                          max(arrival[item["event_id"]] for item in path))
    return list(alerts.values()), notes


def add_alert(alerts, event, rule, evidence, started):
    alerts[event["event_id"]] = {
        "anchor_event_id": event["event_id"], "rule": rule, "actor": event["actor"],
        "services": sorted({item[field] for item in evidence
                            for field in ("source_service", "target_service")}),
        "evidence_event_ids": [item["event_id"] for item in evidence],
        "latency_ms": round((time.perf_counter() - started) * 1000, 4),
    }
