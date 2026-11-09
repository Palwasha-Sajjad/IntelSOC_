"""Worker-level 4625 -> 4624 tests. Never access production PostgreSQL."""
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from app.workers import analysis_worker as worker

BASE = datetime(2026, 11, 10, 1, 0, tzinfo=timezone.utc)
DEVICE = str(uuid4())


def event(number, seconds, *, user="analyst", source="-", logon_type=2):
    inserts = ["-"] * (27 if number == 4624 else 21)
    if number == 4624:
        inserts[5], inserts[6], inserts[8], inserts[18] = (
            user, "LAB", str(logon_type), source,
        )
    else:
        inserts[5], inserts[6], inserts[10], inserts[19] = (
            user, "LAB", str(logon_type), source,
        )
    return {
        "event_id": str(uuid4()),
        "device_id": DEVICE,
        "event_time": BASE + timedelta(seconds=seconds),
        "raw_event": {
            "EventID": number, "Channel": "Security",
            "ProviderName": "Microsoft-Windows-Security-Auditing",
            "StringInserts": inserts,
        },
    }


class Result:
    def __init__(self, name, created):
        setattr(self, name, uuid4())
        self.created = created


def wire(monkeypatch, pending, history, *, created=True):
    monkeypatch.setattr(
        worker, "fetch_unprocessed_auth_success_events",
        lambda limit: pending,
    )
    monkeypatch.setattr(
        worker, "fetch_auth_correlation_context",
        lambda success_event: history,
    )
    monkeypatch.setattr(
        worker, "persist_detection",
        lambda candidate: Result("detection_id", created),
    )
    monkeypatch.setattr(
        worker, "create_alert_for_detection",
        lambda detection_id: Result("alert_id", created),
    )
    monkeypatch.setattr(
        worker, "correlate_alert_to_incident",
        lambda alert_id: Result("incident_id", created),
    )


def test_worker_creates_detection_alert_incident_and_per_rule_state(monkeypatch):
    history = [event(4625, i * 20) for i in range(5)]
    success = event(4624, 110)
    wire(monkeypatch, [success], history)
    marked = []
    monkeypatch.setattr(
        worker, "mark_event_analysis_processed",
        lambda event_id, rule_id: marked.append((event_id, rule_id)),
    )
    result = worker.analyze_auth_correlation_once()
    assert result["detections_created"] == 1
    assert result["alerts_created"] == 1
    assert result["incidents_created"] == 1
    assert result["events_processed"] == 1
    assert result["events_failed"] == 0
    assert marked == [(UUID(success["event_id"]), "RULE-WIN-008")]


def test_worker_retry_reuses_persisted_chain(monkeypatch):
    history = [event(4625, i * 20) for i in range(5)]
    success = event(4624, 110)
    wire(monkeypatch, [success], history, created=False)
    monkeypatch.setattr(
        worker, "mark_event_analysis_processed",
        lambda event_id, rule_id: None,
    )
    result = worker.analyze_auth_correlation_once()
    assert result["detections_reused"] == 1
    assert result["alerts_reused"] == 1
    assert result["incidents_reused"] == 1
    assert result["detections_created"] == 0


def test_worker_missing_evidence_acknowledged_without_alert(monkeypatch):
    success = event(4624, 110)
    wire(monkeypatch, [success], [])
    marked = []
    monkeypatch.setattr(
        worker, "mark_event_analysis_processed",
        lambda event_id, rule_id: marked.append(rule_id),
    )
    result = worker.analyze_auth_correlation_once()
    assert result["events_processed"] == 1
    assert result["detections_created"] == 0
    assert marked == ["RULE-WIN-008"]


def test_worker_prior_success_prevents_second_alert(monkeypatch):
    history = [event(4625, i * 20) for i in range(5)]
    previous_success = event(4624, 110)
    current_success = event(4624, 120)
    wire(monkeypatch, [current_success], history + [previous_success])
    monkeypatch.setattr(
        worker, "mark_event_analysis_processed",
        lambda event_id, rule_id: None,
    )
    result = worker.analyze_auth_correlation_once()
    assert result["events_processed"] == 1
    assert result["detections_created"] == 0


def test_worker_failure_isolated_and_retryable(monkeypatch):
    success = event(4624, 110)
    history = [event(4625, i * 20) for i in range(5)]
    wire(monkeypatch, [success], history)
    monkeypatch.setattr(
        worker, "persist_detection",
        lambda candidate: (_ for _ in ()).throw(RuntimeError("db unavailable")),
    )
    failures = []
    monkeypatch.setattr(
        worker, "mark_event_analysis_failed",
        lambda event_id, message, rule_id:
        failures.append((event_id, message, rule_id)),
    )
    result = worker.analyze_auth_correlation_once()
    assert result["events_failed"] == 1
    assert result["events_processed"] == 0
    assert failures == [
        (UUID(success["event_id"]), "db unavailable", "RULE-WIN-008")
    ]
