"""Bounded, read-only observation of a single controlled baseline fixture."""
import sqlite3
import time

from .db import deadline

POLL_SECONDS = 0.025
MAX_POLLS = 40
MAX_EVENTS = 256


class AuditObserver:
    def __init__(self, guard, operator, publish):
        self.guard = guard
        self.operator = operator
        self.publish = publish
        self.events = []
        self.samples = []
        self.findings = {}
        self.problems = {}
        self.previous_poll = None
        self.current_versions = {}

    def report_budget_gap(self, stage, missing, *, poll_attempted):
        missing_ids = sorted(missing)
        key = ("poll_budget_exhausted", stage, tuple(missing_ids), poll_attempted)
        if key in self.problems:
            return
        notice = {
            "rule": "poll_budget_exhausted", "rule_version": 1, "stage": stage,
            "poll_attempted": poll_attempted, "missing_request_ids": missing_ids,
            "explanation": (
                "The poll budget ended before all required observations were authenticated."
                if poll_attempted else "The poll budget was already exhausted. This checkpoint was skipped."
            ),
        }
        self.problems[key] = notice
        self.publish({"type": "monitor_status", **notice})

    def poll(self, stage, responses=()):
        """Poll inside a running scenario and correlate request-specific HTTP observations."""
        responses = {item["request_id"]: item for item in responses}
        remaining = MAX_POLLS - len(self.samples)
        if remaining <= 0:
            self.report_budget_gap(stage, responses.keys() - self.findings.keys(), poll_attempted=False)
            return
        for _ in range(remaining):
            started = time.monotonic()
            interval = None if self.previous_poll is None else (started - self.previous_poll) * 1000
            self.previous_poll = started
            token = deadline.set(started + 0.25)
            try:
                events = self.guard.evidence(self.operator, max_events=MAX_EVENTS)
                if events[:len(self.events)] != self.events:
                    raise ValueError("Observed audit prefix changed")
            except (ValueError, PermissionError, OSError, sqlite3.Error) as exc:
                integrity = str(exc) in {"Audit integrity check failed", "Audit head mismatch",
                                         "Observed audit prefix changed"}
                reason = "audit_integrity_failure" if integrity else "evidence_unavailable"
                if reason not in self.problems:
                    self.problems[reason] = {
                        "rule": reason, "rule_version": 1, "stage": stage,
                        "explanation": "No authenticated records could be read at this checkpoint.",
                    }
                    self.publish({"type": "monitor_status", **self.problems[reason]})
                events = None
            finally:
                deadline.reset(token)
            observed = time.time()
            observed_monotonic = time.monotonic()
            self.samples.append({"stage": stage, "poll_gap_ms": interval,
                                 "verification_ms": (time.monotonic() - started) * 1000,
                                 "verified": events is not None})
            if events is not None:
                for event in events[len(self.events):]:
                    self.classify(event, stage, observed, observed_monotonic)
                self.events = events
            for request_id, response in responses.items():
                if request_id in self.findings:
                    finding = self.findings[request_id]
                    if (finding["decision"] == "deny" and response["status"] in (401, 403)
                            and response["body_withheld"] and response["reason"] == finding["reason"]
                            and response["node"] == finding["node"]
                            and finding["containment"] == "UNCONFIRMED"):
                        finding["containment"] = "CONFIRMED_DENIAL_NO_BODY"
                        self.publish({"type": "containment", **finding})
            missing = responses.keys() - self.findings.keys()
            if not missing:
                return
            if len(self.samples) >= MAX_POLLS:
                self.report_budget_gap(stage, missing, poll_attempted=True)
                return
            if events is None:
                return
            time.sleep(POLL_SECONDS)

    def classify(self, event, stage, observed, observed_monotonic):
        if event.get("decision") != "deny":
            return
        action, reason = event["action"], event["reason"]
        if action == "read" and reason == "revoked_device":
            rule, explanation = "revoked_device_read", "Worker denied a read from a revoked device."
        elif action == "rotate" and reason.startswith("approval_"):
            rule, explanation = "invalid_rotation_approval", "Worker denied a rotation with an invalid approval."
        elif action == "read" and reason == "wrong_version":
            current = self.current_versions.get(event["target"])
            if current is not None and type(event["version"]) is int and event["version"] < current:
                rule = "retired_version_read"
                explanation = "Worker rejected a version older than the fixture's verified readable version."
            else:
                rule, explanation = "version_read_rejected", "Worker rejected the requested key version."
        elif action in {"read", "rotate", "revoke", "enroll"}:
            rule, explanation = "authorization_failure", "Worker denied a protected operation."
        else:
            return
        request_id = event["request_id"]
        if request_id in self.findings:
            return
        identity = event.get("credential_ref")
        related = [item["event_id"] for item in self.findings.values()
                   if identity and item["credential_ref"] == identity
                   and item["target"] == event.get("target")
                   and 0 <= event["timestamp"] - item["audit_timestamp"] <= 5]
        finding = {
            "rule": rule, "rule_version": 1, "explanation": explanation,
            "actor": event.get("actor"), "credential_ref": identity, "node": event["node"],
            "event_id": event["id"], "request_id": request_id, "action": action,
            "decision": event["decision"], "reason": reason, "target": event["target"],
            "version": event["version"], "stage": stage, "related_event_ids": related,
            "audit_timestamp": event["timestamp"],
            "audit_to_observation_ms": (observed - event["timestamp"]) * 1000,
            "observation_to_alert_ms": (time.monotonic() - observed_monotonic) * 1000,
            "containment": "UNCONFIRMED", "administrative_response": "NONE",
            "recommendation": "Review related denied requests." if related else None,
        }
        self.findings[request_id] = finding
        self.publish({"type": "finding", **finding})

    def result(self):
        return {"findings": list(self.findings.values()), "status_events": list(self.problems.values()),
                "poll_samples": self.samples, "retry_poll_interval_ms": POLL_SECONDS * 1000,
                "poll_budget": MAX_POLLS, "record_budget": MAX_EVENTS}
