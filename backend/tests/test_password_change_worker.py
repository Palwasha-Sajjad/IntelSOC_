"""Focused WIN-007 integration tests without production database writes."""
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.workers import analysis_worker as worker

NOW = datetime(2026, 11, 9, 15, 0, tzinfo=timezone.utc)


def record(*, event_id=4723):
    return {
        "event_id": str(uuid4()),
        "device_id": str(uuid4()),
        "event_time": NOW,
        "raw_event": {
            "EventID": event_id,
            "Channel": "Security",
            "ProviderName": "Microsoft-Windows-Security-Auditing",
            "StringInserts": ["testuser", "LAB", "S-1-5-21-1-2-3-1001",
                              "S-1-5-21-1-2-3-1001", "testuser", "LAB"],
        },
    }


class Result:
    def __init__(self, identifier, *, created):
        setattr(self, identifier, uuid4())
        self.created = created


def wire(monkeypatch, events, *, created=True):
    monkeypatch.setattr(
        worker, "fetch_unprocessed_password_change_events",
        lambda limit: events,
    )
    monkeypatch.setattr(worker, "persist_detection",
                        lambda candidate: Result("detection_id", created=created))
    monkeypatch.setattr(worker, "create_alert_for_detection",
                        lambda detection_id: Result("alert_id", created=created))
    monkeypatch.setattr(worker, "correlate_alert_to_incident",
                        lambda alert_id: Result("incident_id", created=created))


def test_win007_persists_and_marks_only_its_rule(monkeypatch):
    item = record()
    wire(monkeypatch, [item])
    processed = []
    monkeypatch.setattr(worker, "mark_event_analysis_processed",
                        lambda event_id, rule_id: processed.append((event_id, rule_id)))
    result = worker.analyze_password_change_once()
    assert result["events_processed"] == 1
    assert result["detections_created"] == 1
    assert result["alerts_created"] == 1
    assert result["incidents_created"] == 1
    assert result["events_failed"] == 0
    assert processed == [(uuid4_from_str(item["event_id"]), "RULE-WIN-007")]


def uuid4_from_str(value):
    from uuid import UUID
    return UUID(value)


def test_win007_retry_reuses_detection_alert_and_incident(monkeypatch):
    wire(monkeypatch, [record()], created=False)
    monkeypatch.setattr(worker, "mark_event_analysis_processed",
                        lambda event_id, rule_id: None)
    result = worker.analyze_password_change_once()
    assert result["detections_reused"] == 1
    assert result["alerts_reused"] == 1
    assert result["incidents_reused"] == 1
    assert result["detections_created"] == 0


def test_win007_error_keeps_only_its_rule_retryable(monkeypatch):
    wire(monkeypatch, [record()])
    monkeypatch.setattr(
        worker, "correlate_alert_to_incident",
        lambda alert_id: (_ for _ in ()).throw(RuntimeError("incident unavailable")),
    )
    failed = []
    monkeypatch.setattr(worker, "mark_event_analysis_failed",
                        lambda event_id, error, rule_id:
                        failed.append((error, rule_id)))
    monkeypatch.setattr(worker, "mark_event_analysis_processed",
                        lambda *args: pytest.fail("Must not mark failed event processed"))
    result = worker.analyze_password_change_once()
    assert result["events_failed"] == 1
    assert result["events_processed"] == 0
    assert failed == [("incident unavailable", "RULE-WIN-007")]


def test_win007_no_pending_is_noop(monkeypatch):
    wire(monkeypatch, [])
    result = worker.analyze_password_change_once()
    assert result["events_processed"] == 0
    assert result["detections_created"] == 0
    assert result["events_failed"] == 0
