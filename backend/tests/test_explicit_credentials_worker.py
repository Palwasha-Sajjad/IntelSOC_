"""WIN-012 worker rule isolation, persistence, and retry behavior."""
from datetime import datetime, timezone
from uuid import UUID, uuid4

from app.workers import analysis_worker as worker

NOW = datetime(2026, 11, 10, tzinfo=timezone.utc)


def event(*, suspicious=True):
    return {
        "event_id": str(uuid4()),
        "device_id": str(uuid4()),
        "event_time": NOW,
        "raw_event": {
            "EventID": 4648,
            "Channel": "Security",
            "ProviderName": "Microsoft-Windows-Security-Auditing",
            "StringInserts": [
                "sid", "alice", "LAB", "0x1", "guid", "admin", "LAB",
                "guid", "server", "additional", "0x123",
                "powershell.exe" if suspicious else "svchost.exe",
                "192.168.1.18", "445",
            ],
        },
    }


class Saved:
    def __init__(self, field, created=True):
        setattr(self, field, uuid4())
        self.created = created


def wire(monkeypatch, items, *, created=True):
    monkeypatch.setattr(
        worker, "fetch_unprocessed_explicit_credential_events",
        lambda limit: items,
    )
    monkeypatch.setattr(
        worker, "persist_detection",
        lambda candidate: Saved("detection_id", created),
    )
    monkeypatch.setattr(
        worker, "create_alert_for_detection",
        lambda detection_id: Saved("alert_id", created),
    )
    monkeypatch.setattr(
        worker, "correlate_alert_to_incident",
        lambda alert_id: Saved("incident_id", created),
    )


def test_positive_persists_and_acks_only_win012(monkeypatch):
    item = event()
    wire(monkeypatch, [item])
    processed = []
    monkeypatch.setattr(
        worker, "mark_event_analysis_processed",
        lambda event_id, rule_id: processed.append((event_id, rule_id)),
    )
    result = worker.analyze_explicit_credentials_once()
    assert result["events_processed"] == 1
    assert result["detections_created"] == 1
    assert result["alerts_created"] == 1
    assert result["incidents_created"] == 1
    assert result["events_failed"] == 0
    assert processed == [(UUID(item["event_id"]), "RULE-WIN-012")]


def test_system_process_is_acknowledged_without_alert(monkeypatch):
    item = event(suspicious=False)
    wire(monkeypatch, [item])
    marked = []
    monkeypatch.setattr(
        worker, "mark_event_analysis_processed",
        lambda event_id, rule_id: marked.append(rule_id),
    )
    result = worker.analyze_explicit_credentials_once()
    assert result["events_processed"] == 1
    assert result["alerts_created"] == 0
    assert marked == ["RULE-WIN-012"]


def test_replay_reuses_persistence(monkeypatch):
    wire(monkeypatch, [event()], created=False)
    monkeypatch.setattr(
        worker, "mark_event_analysis_processed", lambda *args: None,
    )
    result = worker.analyze_explicit_credentials_once()
    assert result["detections_reused"] == 1
    assert result["alerts_reused"] == 1
    assert result["incidents_reused"] == 1
    assert result["detections_created"] == 0


def test_failed_persistence_marks_retry_not_acknowledge(monkeypatch):
    item = event()
    wire(monkeypatch, [item])
    monkeypatch.setattr(
        worker, "create_alert_for_detection",
        lambda detection_id: (_ for _ in ()).throw(RuntimeError("db unavailable")),
    )
    errors = []
    monkeypatch.setattr(
        worker, "mark_event_analysis_failed",
        lambda event_id, error, rule_id: errors.append((event_id, error, rule_id)),
    )
    monkeypatch.setattr(
        worker, "mark_event_analysis_processed",
        lambda *args: (_ for _ in ()).throw(AssertionError("must not acknowledge")),
    )
    result = worker.analyze_explicit_credentials_once()
    assert result["events_failed"] == 1
    assert result["events_processed"] == 0
    assert errors == [(UUID(item["event_id"]), "db unavailable", "RULE-WIN-012")]
