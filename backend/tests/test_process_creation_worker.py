"""WIN-010 rule worker state and persistence regressions."""
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
            "EventID": 4688,
            "ProviderName": "Microsoft-Windows-Security-Auditing",
            "Channel": "Security",
            "StringInserts": [
                "sid", "user", "LAB", "0x1", "0x2", "powershell.exe",
                "%%1936", "0x3",
                "powershell.exe -enc SQBFAFgA" if suspicious else
                "powershell.exe -File backup.ps1",
            ],
        },
    }


class Result:
    def __init__(self, field, created=True):
        setattr(self, field, uuid4())
        self.created = created


def wire(monkeypatch, items, *, created=True):
    monkeypatch.setattr(
        worker, "fetch_unprocessed_process_creation_events",
        lambda limit: items,
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


def test_suspicious_process_persists_and_marks_only_win010(monkeypatch):
    item = event()
    wire(monkeypatch, [item])
    ack = []
    monkeypatch.setattr(
        worker, "mark_event_analysis_processed",
        lambda id, rule: ack.append((id, rule)),
    )
    result = worker.analyze_process_creations_once()
    assert result["events_processed"] == 1
    assert result["detections_created"] == 1
    assert result["alerts_created"] == 1
    assert result["incidents_created"] == 1
    assert result["events_failed"] == 0
    assert ack == [(UUID(item["event_id"]), "RULE-WIN-010")]


def test_normal_process_is_acknowledged_without_alert(monkeypatch):
    wire(monkeypatch, [event(suspicious=False)])
    ack = []
    monkeypatch.setattr(
        worker, "mark_event_analysis_processed",
        lambda id, rule: ack.append((id, rule)),
    )
    result = worker.analyze_process_creations_once()
    assert result["events_processed"] == 1
    assert result["alerts_created"] == 0
    assert len(ack) == 1 and ack[0][1] == "RULE-WIN-010"


def test_replay_reuses_existing_records(monkeypatch):
    wire(monkeypatch, [event()], created=False)
    monkeypatch.setattr(worker, "mark_event_analysis_processed", lambda *args: None)
    result = worker.analyze_process_creations_once()
    assert result["detections_reused"] == 1
    assert result["alerts_reused"] == 1
    assert result["incidents_reused"] == 1
    assert result["detections_created"] == 0


def test_failure_marks_retry_without_acknowledging(monkeypatch):
    item = event()
    wire(monkeypatch, [item])
    monkeypatch.setattr(
        worker, "create_alert_for_detection",
        lambda id: (_ for _ in ()).throw(RuntimeError("database offline")),
    )
    failures = []
    monkeypatch.setattr(
        worker, "mark_event_analysis_failed",
        lambda event_id, msg, rule: failures.append((event_id, msg, rule)),
    )
    monkeypatch.setattr(
        worker, "mark_event_analysis_processed",
        lambda *args: (_ for _ in ()).throw(AssertionError("should not ack")),
    )
    result = worker.analyze_process_creations_once()
    assert result["events_failed"] == 1
    assert result["events_processed"] == 0
    assert failures == [(UUID(item["event_id"]), "database offline", "RULE-WIN-010")]
