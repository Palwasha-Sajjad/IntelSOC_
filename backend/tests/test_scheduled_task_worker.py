"""WIN-009 worker isolation, retry, benign events and persistence."""
from datetime import datetime, timezone
from uuid import UUID, uuid4

from app.workers import analysis_worker as worker

NOW = datetime(2026, 11, 10, 2, 0, tzinfo=timezone.utc)


def event(*, suspicious=True, number=4698):
    args = "-EncodedCommand SQBFAFgA" if suspicious else "-File backup.ps1"
    xml = (
        '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
        '<Actions><Exec><Command>powershell.exe</Command>'
        f'<Arguments>{args}</Arguments></Exec></Actions></Task>'
    )
    return {
        "event_id": str(uuid4()),
        "device_id": str(uuid4()),
        "event_time": NOW,
        "raw_event": {
            "EventID": number,
            "Channel": "Security",
            "ProviderName": "Microsoft-Windows-Security-Auditing",
            "StringInserts": ["sid", "admin", "LAB", "0x1",
                              r"\IntelSOC-Demo", xml],
        },
    }


class Result:
    def __init__(self, field, created=True):
        setattr(self, field, uuid4())
        self.created = created


def wire(monkeypatch, records, *, created=True):
    monkeypatch.setattr(
        worker, "fetch_unprocessed_scheduled_task_events",
        lambda limit: records,
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


def test_worker_creates_alert_incident_and_independent_state(monkeypatch):
    item = event()
    wire(monkeypatch, [item])
    marked = []
    monkeypatch.setattr(
        worker, "mark_event_analysis_processed",
        lambda event_id, rule_id: marked.append((event_id, rule_id)),
    )
    result = worker.analyze_scheduled_tasks_once()
    assert result["detections_created"] == 1
    assert result["alerts_created"] == 1
    assert result["incidents_created"] == 1
    assert result["events_processed"] == 1
    assert result["events_failed"] == 0
    assert marked == [(UUID(item["event_id"]), "RULE-WIN-009")]


def test_worker_benign_record_processed_without_alert(monkeypatch):
    wire(monkeypatch, [event(suspicious=False)])
    monkeypatch.setattr(
        worker, "mark_event_analysis_processed",
        lambda event_id, rule_id: None,
    )
    result = worker.analyze_scheduled_tasks_once()
    assert result["events_processed"] == 1
    assert result["detections_created"] == 0
    assert result["alerts_created"] == 0


def test_worker_idempotent_reuse(monkeypatch):
    wire(monkeypatch, [event(number=4702)], created=False)
    monkeypatch.setattr(
        worker, "mark_event_analysis_processed",
        lambda event_id, rule_id: None,
    )
    result = worker.analyze_scheduled_tasks_once()
    assert result["detections_reused"] == 1
    assert result["alerts_reused"] == 1
    assert result["incidents_reused"] == 1
    assert result["detections_created"] == 0


def test_worker_failure_isolated_for_retry(monkeypatch):
    item = event()
    wire(monkeypatch, [item])
    monkeypatch.setattr(
        worker, "create_alert_for_detection",
        lambda detection_id: (_ for _ in ()).throw(RuntimeError("db unavailable")),
    )
    failures = []
    monkeypatch.setattr(
        worker, "mark_event_analysis_failed",
        lambda event_id, error, rule_id:
        failures.append((event_id, error, rule_id)),
    )
    monkeypatch.setattr(
        worker, "mark_event_analysis_processed",
        lambda *args: (_ for _ in ()).throw(AssertionError("Unexpected ack")),
    )
    result = worker.analyze_scheduled_tasks_once()
    assert result["events_failed"] == 1
    assert result["events_processed"] == 0
    assert failures == [(UUID(item["event_id"]), "db unavailable", "RULE-WIN-009")]
