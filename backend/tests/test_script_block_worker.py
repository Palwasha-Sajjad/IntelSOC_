"""WIN-011 worker persistence, replays, benign blocks and retry isolation."""
from datetime import datetime, timezone
from uuid import UUID, uuid4
from app.workers import analysis_worker as worker

NOW = datetime(2026, 11, 10, tzinfo=timezone.utc)


def event(part=1, total=1, content="IEX ([Convert]::FromBase64String('QQ=='))"):
    return {
        "event_id": str(uuid4()),
        "device_id": "device-a",
        "event_time": NOW,
        "raw_event": {
            "EventID": 4104,
            "Channel": "Microsoft-Windows-PowerShell/Operational",
            "ProviderName": "Microsoft-Windows-PowerShell",
            "StringInserts": [str(part), str(total), content, "block-one", ""],
        },
    }


class Saved:
    def __init__(self, field, created=True):
        setattr(self, field, uuid4())
        self.created = created


def wire(monkeypatch, groups, *, created=True):
    monkeypatch.setattr(
        worker, "fetch_pending_script_block_groups", lambda limit: groups,
    )
    monkeypatch.setattr(
        worker, "persist_detection",
        lambda candidate: Saved("detection_id", created),
    )
    monkeypatch.setattr(
        worker, "create_alert_for_detection",
        lambda id: Saved("alert_id", created),
    )
    monkeypatch.setattr(
        worker, "correlate_alert_to_incident",
        lambda id: Saved("incident_id", created),
    )


def test_complete_block_persists_and_acknowledges_only_win011(monkeypatch):
    a, b = event(1, 2, "Invoke-Ex"), event(
        2, 2, "pression ([Convert]::FromBase64String('QQ=='))",
    )
    wire(monkeypatch, [[a, b]])
    acknowledged = []
    monkeypatch.setattr(
        worker, "mark_event_analysis_processed",
        lambda id, rule: acknowledged.append((id, rule)),
    )
    result = worker.analyze_script_blocks_once()
    assert result["events_processed"] == 2
    assert result["detections_created"] == 1
    assert result["alerts_created"] == 1
    assert result["incidents_created"] == 1
    assert acknowledged == [
        (UUID(a["event_id"]), "RULE-WIN-011"),
        (UUID(b["event_id"]), "RULE-WIN-011"),
    ]


def test_incomplete_block_deferred_without_acknowledgment(monkeypatch):
    wire(monkeypatch, [[event(1, 2)]])
    monkeypatch.setattr(
        worker, "mark_event_analysis_processed",
        lambda *args: (_ for _ in ()).throw(AssertionError("ACK incomplete")),
    )
    result = worker.analyze_script_blocks_once()
    assert result["events_processed"] == 0
    assert result["alerts_created"] == 0


def test_benign_block_acknowledged(monkeypatch):
    wire(monkeypatch, [[event(content="Get-Date")]])
    seen = []
    monkeypatch.setattr(
        worker, "mark_event_analysis_processed",
        lambda id, rule: seen.append(rule),
    )
    result = worker.analyze_script_blocks_once()
    assert result["events_processed"] == 1
    assert result["detections_created"] == 0
    assert seen == ["RULE-WIN-011"]


def test_replay_uses_existing_detection_alert_incident(monkeypatch):
    wire(monkeypatch, [[event()]], created=False)
    monkeypatch.setattr(
        worker, "mark_event_analysis_processed", lambda *args: None,
    )
    result = worker.analyze_script_blocks_once()
    assert result["detections_reused"] == 1
    assert result["alerts_reused"] == 1
    assert result["incidents_reused"] == 1
    assert result["detections_created"] == 0


def test_persistence_failure_marks_failed_not_processed(monkeypatch):
    item = event()
    wire(monkeypatch, [[item]])
    monkeypatch.setattr(
        worker, "create_alert_for_detection",
        lambda id: (_ for _ in ()).throw(RuntimeError("db down")),
    )
    errors = []
    monkeypatch.setattr(
        worker, "mark_event_analysis_failed",
        lambda id, err, rule: errors.append((id, err, rule)),
    )
    monkeypatch.setattr(
        worker, "mark_event_analysis_processed",
        lambda *args: (_ for _ in ()).throw(AssertionError("Unexpected ACK")),
    )
    result = worker.analyze_script_blocks_once()
    assert result["events_failed"] == 1
    assert result["events_processed"] == 0
    assert errors == [(UUID(item["event_id"]), "db down", "RULE-WIN-011")]
