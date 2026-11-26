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


class Detector:
    """Incremental evaluator for a finite set of sessions in receipt order."""

    def __init__(self, approvals):
        self.approvals = {item["approval_id"]: item for item in approvals}
        self.receipts = {}
        self.changes = defaultdict(list)
        self.pending_reads = defaultdict(list)
        self.paths = defaultdict(dict)
        self.generic_reads = {}
        self.emitted = set()
        self.uncertain = set()

    def alert(self, event, rule, evidence):
        anchor = event["event_id"]
        key = (anchor, rule)
        if key in self.emitted:
            return None
        self.emitted.add(key)
        return {
            "anchor_event_id": anchor, "rule": rule, "actor": event["actor"],
            "services": sorted({item[field] for item in evidence
                                for field in ("source_service", "target_service")}),
            "evidence_event_ids": [item["event_id"] for item in evidence],
            "latency_ms": round((time.perf_counter() - max(
                self.receipts[item["event_id"]] for item in evidence
            )) * 1000, 4),
        }

    def ingest(self, event, *, received_at=None):
        event_id = event["event_id"]
        if event_id in self.receipts:
            return [], []
        self.receipts[event_id] = time.perf_counter() if received_at is None else received_at
        key = event["actor"], event["session_id"]
        when = corrected(event)
        late = abs(timestamp(event["received_time_utc"]) - when) > LATENESS_SECONDS
        alerts = []
        notes = [{"event": event_id, "reason": "arrival_outside_window"}] if late else []

        if event["action"] == "role_change" and event["outcome"] == "success":
            if not approved(event, self.approvals):
                alerts.append(self.alert(event, "unexpected_role_change", [event]))
                if not late:
                    self.changes[key].append((when, event))
                    remaining = []
                    for read_when, read in self.pending_reads[key]:
                        match = self.correlate(read, read_when, [(when, event)], notes)
                        if match:
                            alerts.append(match)
                        else:
                            remaining.append((read_when, read))
                    self.pending_reads[key] = remaining
            return alerts, notes

        if late or event["action"] not in {"read", "list_roles"}:
            return alerts, notes

        if event["outcome"] == "allow":
            approval = self.approvals.get(event["approval_id"])
            target = event["target_service"]
            role = event["role_after"]
            if (approval and approval["operation"] == "grant_role" and target != "catalog"
                    and (not approved(event, self.approvals) or target not in approval.get("scope", ()))):
                alerts.append(self.alert(event, "access_outside_approval", [event]))
            else:
                match = self.correlate(event, when, self.changes[key], notes)
                if match:
                    alerts.append(match)
                else:
                    self.pending_reads[key].append((when, event))
                    if role in ROLE_TARGETS and target not in ROLE_TARGETS[role]:
                        self.generic_reads[event_id] = event

        alerts.extend(self.path_alerts(event, key))
        return alerts, notes

    def correlate(self, read, when, changes, notes):
        read_id = read["event_id"]
        earlier = []
        for change_time, change in changes:
            delta = when - change_time
            if abs(delta) <= 2 * UNCERTAINTY_SECONDS:
                if read_id not in self.uncertain:
                    notes.append({"event": read_id, "reason": "order_uncertain"})
                    self.uncertain.add(read_id)
            elif delta > 0:
                earlier.append((change_time, change))
        if earlier:
            _, cause = max(earlier, key=lambda item: (item[0], item[1]["event_id"]))
            self.generic_reads.pop(read_id, None)
            return self.alert(read, "review_after_role_change", [cause, read])
        return None

    def path_alerts(self, event, key):
        role = event["role_after"]
        edge = event["source_service"], event["target_service"]
        if role not in SERVICE_EDGES or edge in SERVICE_EDGES[role]:
            return []
        path = self.paths[(*key, event["correlation_id"])]
        other_edge = next((candidate for candidate in path if candidate != edge), None)
        is_second_edge = len(path) == 1 and other_edge is not None
        path.setdefault(edge, []).append(event)
        if other_edge is None:
            return []
        alerts = [self.alert(event, "lateral_movement_candidate", [event, path[other_edge][0]])]
        if is_second_edge:
            alerts.extend(self.alert(anchor, "lateral_movement_candidate", [anchor, event])
                          for anchor in path[other_edge])
        return alerts

    def finish(self):
        """Emit generic fallback alerts after the caller closes the input."""
        alerts = [self.alert(event, "unexpected_allowed_access", [event])
                  for event in self.generic_reads.values()]
        self.generic_reads.clear()
        return alerts


def analyze(events, approvals):
    detector = Detector(approvals)
    alerts, notes = [], []
    for event in events:
        new_alerts, new_notes = detector.ingest(event)
        alerts.extend(new_alerts)
        notes.extend(new_notes)
    alerts.extend(detector.finish())
    return alerts, notes
