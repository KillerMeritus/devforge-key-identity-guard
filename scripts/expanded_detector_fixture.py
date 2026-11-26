"""Scenario-authored labels for an expanded deterministic synthetic replay."""
from datetime import datetime, timedelta, timezone


ORIGIN = datetime(2026, 7, 1, tzinfo=timezone.utc)
BLOCKS = 12


def generate():
    events, approvals, expected, benign, contested = [], [], [], [], []
    for block in range(BLOCKS):
        start = block * 3600
        prefix = f"cohort-{block:02d}"

        def stamp(seconds):
            return (ORIGIN + timedelta(seconds=start + seconds)).isoformat()

        def add(name, at, actor, *, received=None, action="read", role="viewer", outcome="allow",
                source="portal", target="catalog", approval="", flow="main", offset=0,
                label=None, conflict=False):
            identity = f"{prefix}-{actor}"
            item = {
                "event_id": f"{prefix}-{name}", "event_time_utc": stamp(at + offset / 1000),
                "received_time_utc": stamp(at + 0.1 if received is None else received),
                "source_clock_offset_ms": offset, "actor": identity, "session_id": identity,
                "correlation_id": flow, "action": action, "outcome": outcome,
                "role_after": role, "source_service": source, "target_service": target,
                "approval_id": approval,
            }
            events.append(item)
            if conflict:
                contested.append(item["event_id"])
            elif label:
                expected.append({"event_id": item["event_id"], "rule": label})
            else:
                benign.append(item["event_id"])
            return item

        for row in range(90):
            at = 30 + row
            if row % 3 == 0:
                add(f"routine-{row}", at, f"user-{row % 17}", action="list_roles",
                    source=("portal", "identity", "console")[row % 3], offset=(row % 5 - 2) * 1000)
            elif row % 3 == 1:
                add(f"routine-{row}", at, f"worker-{row % 11}", role="service-reader",
                    source="reports", target="catalog", offset=(row % 5 - 2) * 1000)
            else:
                add(f"routine-{row}", at, f"guest-{row % 13}", outcome="deny",
                    target=("records", "archive", "metrics", "ledger")[row % 4],
                    offset=(row % 5 - 2) * 1000)

        approval = prefix + "-approval"
        scoped_target = ("reports", "reports-node-a", "reports-node-b")[block % 3]
        approvals.append({
            "approval_id": approval, "subject": prefix + "-approved", "operation": "grant_role",
            "role": "report-reader", "scope": [scoped_target],
            "valid_from_utc": stamp(0), "valid_until_utc": stamp(8),
        })
        add("approved-grant", 1, "approved", action="role_change", role="report-reader",
            outcome="success", target="identity", approval=approval)
        add("in-scope", 2, "approved", role="report-reader", target=scoped_target, approval=approval)
        add("out-of-scope", 3, "approved", role="report-reader", target="finance", approval=approval,
            label="access_outside_approval")
        add("expired", 8, "approved", role="report-reader", target=scoped_target, approval=approval,
            label="access_outside_approval")
        add("unapproved-grant", 10, "other", received=11.5, action="role_change", role="operator",
            outcome="success", target="identity", label="unexpected_role_change")
        add("reordered-read", 11, "other", received=11.2, role="operator", target="catalog",
            offset=-1500, label="review_after_role_change")
        add("overlap", 10.1, "other", received=11.8, role="operator", target="catalog", offset=1500)

        service = ("ledger", "archive", "metrics", "orders")[block % 4]
        add("edge-one", 15, "path", role="service-reader", source="reports", target=service,
            outcome="deny", label="lateral_movement_candidate")
        add("edge-two", 16, "path", role="service-reader", source=service, target="backup",
            outcome="deny", label="lateral_movement_candidate")
        add("unrelated-one", 17, "path", role="service-reader", source="reports", target=service,
            outcome="deny", flow="unrelated-one")
        add("unrelated-two", 18, "path", role="service-reader", source=service, target="backup",
            outcome="deny", flow="unrelated-two")
        add("late", 19, "late-user", received=25, target="catalog")
        repeated = add("exact-duplicate", 26, "duplicate")
        events.append(dict(repeated))
        disputed = add("contested", 27, "conflict", action="role_change", role="operator",
                       outcome="success", target="identity", conflict=True)
        events.append(dict(disputed, outcome="deny"))
        add("unrelated-after-conflict", 28, "conflict", role="operator", target="catalog")

    # Receipt times are normalized UTC text. Stable sorting preserves ties and deliberate reordering.
    events.sort(key=lambda event: event["received_time_utc"])
    return {"events": events, "approvals": approvals, "expected": expected,
            "benign_event_ids": benign, "contested_event_ids": contested}
