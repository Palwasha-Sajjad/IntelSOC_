from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.workers import analysis_worker


@pytest.fixture(autouse=True)
def isolate_source_ip_enrichment(monkeypatch):
    """Worker unit tests must never contact PostgreSQL for IP enrichment."""
    monkeypatch.setattr(
        analysis_worker,
        "enrich_pending_windows_4625_ips",
        lambda pending: 0,
    )


BASE_TIME = datetime(
    2026,
    11,
    9,
    5,
    50,
    0,
    tzinfo=timezone.utc,
)


def event(number: int, seconds: int):
    return {
        "event_id": str(uuid4()),
        "device_id": str(uuid4()),
        "event_time": BASE_TIME + timedelta(seconds=seconds),
        "raw_event": {
            "Channel": "Security",
            "EventID": 4625,
            "ProviderName": (
                "Microsoft-Windows-Security-Auditing"
            ),
            "StringInserts": [
                "sid",
                "requestor",
                "LAB",
                "0x1",
                "S-1-0-0",
                "testuser",
                "LAB",
                "0xc000006e",
                "%%2313",
                "0xc000006e",
                2,
                "Advapi",
                "Negotiate",
                "LAB",
                "-",
                "-",
                0,
                "0x1",
                "C:\\Windows\\System32\\winlogon.exe",
                "-",
                "-",
            ],
        },
    }


def same_device_events(count: int):
    device_id = str(uuid4())
    events = [event(i, i * 20) for i in range(count)]

    for item in events:
        item["device_id"] = device_id

    return events


class DetectionResult:
    def __init__(self, *, created: bool):
        self.detection_id = uuid4()
        self.created = created


class AlertResult:
    def __init__(self, *, created: bool):
        self.alert_id = uuid4()
        self.created = created


class IncidentResult:
    def __init__(self, *, created: bool):
        self.incident_id = uuid4()
        self.created = created


def wire_success(monkeypatch, events, *, created=True):
    monkeypatch.setattr(
        analysis_worker,
        "fetch_unprocessed_failed_login_events",
        lambda limit: events,
    )
    monkeypatch.setattr(
        analysis_worker,
        "fetch_failed_login_history",
        lambda start_time, end_time: events,
    )
    monkeypatch.setattr(
        analysis_worker,
        "persist_detection",
        lambda candidate: DetectionResult(created=created),
    )
    monkeypatch.setattr(
        analysis_worker,
        "create_alert_for_detection",
        lambda detection_id: AlertResult(created=created),
    )
    monkeypatch.setattr(
        analysis_worker,
        "correlate_alert_to_incident",
        lambda alert_id: IncidentResult(created=created),
    )
    monkeypatch.setattr(
        analysis_worker,
        "mark_event_analysis_processed",
        lambda event_id: None,
    )
    monkeypatch.setattr(
        analysis_worker,
        "enrich_pending_windows_4625_ips",
        lambda pending: 0,
    )


def test_analyze_once_persists_alert_and_incident(monkeypatch):
    events = same_device_events(5)
    wire_success(monkeypatch, events)

    result = analysis_worker.analyze_once()

    assert result == {
        "events_processed": 5,
        "detections_created": 1,
        "detections_reused": 0,
        "alerts_created": 1,
        "alerts_reused": 0,
        "incidents_created": 1,
        "incidents_reused": 0,
        "events_failed": 0,
    }


def test_history_detection_is_not_persisted_again(monkeypatch):
    history = same_device_events(6)
    pending = [history[-1]]

    monkeypatch.setattr(
        analysis_worker,
        "fetch_unprocessed_failed_login_events",
        lambda limit: pending,
    )
    monkeypatch.setattr(
        analysis_worker,
        "fetch_failed_login_history",
        lambda start_time, end_time: history,
    )

    persisted = []
    alerts = []
    incidents = []

    monkeypatch.setattr(
        analysis_worker,
        "persist_detection",
        lambda candidate: persisted.append(candidate),
    )
    monkeypatch.setattr(
        analysis_worker,
        "create_alert_for_detection",
        lambda detection_id: alerts.append(detection_id),
    )
    monkeypatch.setattr(
        analysis_worker,
        "correlate_alert_to_incident",
        lambda alert_id: incidents.append(alert_id),
    )
    monkeypatch.setattr(
        analysis_worker,
        "mark_event_analysis_processed",
        lambda event_id: None,
    )

    result = analysis_worker.analyze_once()

    assert persisted == []
    assert alerts == []
    assert incidents == []
    assert result["events_processed"] == 1
    assert result["incidents_created"] == 0


def test_no_pending_events_is_noop(monkeypatch):
    monkeypatch.setattr(
        analysis_worker,
        "fetch_unprocessed_failed_login_events",
        lambda limit: [],
    )

    assert analysis_worker.analyze_once() == {
        "events_processed": 0,
        "detections_created": 0,
        "detections_reused": 0,
        "alerts_created": 0,
        "alerts_reused": 0,
        "incidents_created": 0,
        "incidents_reused": 0,
        "events_failed": 0,
    }


def test_analysis_failure_marks_batch_failed(monkeypatch):
    events = same_device_events(2)

    monkeypatch.setattr(
        analysis_worker,
        "fetch_unprocessed_failed_login_events",
        lambda limit: events,
    )
    monkeypatch.setattr(
        analysis_worker,
        "fetch_failed_login_history",
        lambda start_time, end_time: (
            (_ for _ in ()).throw(
                RuntimeError("analysis exploded")
            )
        ),
    )

    failed = []

    monkeypatch.setattr(
        analysis_worker,
        "mark_event_analysis_failed",
        lambda event_id, error: failed.append(
            (str(event_id), error)
        ),
    )

    with pytest.raises(
        RuntimeError,
        match="analysis exploded",
    ):
        analysis_worker.analyze_once()

    assert len(failed) == 2


def test_reused_detection_alert_and_incident_are_counted(monkeypatch):
    events = same_device_events(5)
    wire_success(monkeypatch, events, created=False)

    result = analysis_worker.analyze_once()

    assert result["detections_reused"] == 1
    assert result["alerts_reused"] == 1
    assert result["incidents_reused"] == 1


def test_incident_failure_keeps_batch_retryable(monkeypatch):
    events = same_device_events(5)

    monkeypatch.setattr(
        analysis_worker,
        "fetch_unprocessed_failed_login_events",
        lambda limit: events,
    )
    monkeypatch.setattr(
        analysis_worker,
        "fetch_failed_login_history",
        lambda start_time, end_time: events,
    )
    monkeypatch.setattr(
        analysis_worker,
        "persist_detection",
        lambda candidate: DetectionResult(created=True),
    )
    monkeypatch.setattr(
        analysis_worker,
        "create_alert_for_detection",
        lambda detection_id: AlertResult(created=True),
    )
    monkeypatch.setattr(
        analysis_worker,
        "correlate_alert_to_incident",
        lambda alert_id: (
            (_ for _ in ()).throw(
                RuntimeError("incident correlation failed")
            )
        ),
    )

    processed = []
    failed = []

    monkeypatch.setattr(
        analysis_worker,
        "mark_event_analysis_processed",
        lambda event_id: processed.append(str(event_id)),
    )
    monkeypatch.setattr(
        analysis_worker,
        "mark_event_analysis_failed",
        lambda event_id, error: failed.append(
            (str(event_id), error)
        ),
    )

    with pytest.raises(
        RuntimeError,
        match="incident correlation failed",
    ):
        analysis_worker.analyze_once()

    assert processed == []
    assert len(failed) == 5


def test_enrichment_failure_does_not_suppress_detection(monkeypatch):
    events = same_device_events(5)
    wire_success(monkeypatch, events)
    processed = []
    monkeypatch.setattr(
        analysis_worker,
        "mark_event_analysis_processed",
        lambda event_id: processed.append(str(event_id)),
    )
    monkeypatch.setattr(
        analysis_worker,
        "enrich_pending_windows_4625_ips",
        lambda pending: (_ for _ in ()).throw(
            RuntimeError("enrichment unavailable")
        ),
    )

    result = analysis_worker.analyze_once()

    assert result["events_processed"] == 5
    assert result["detections_created"] == 1
    assert result["alerts_created"] == 1
    assert result["incidents_created"] == 1
    assert len(processed) == 5


def test_enrichment_receives_only_current_pending_batch(monkeypatch):
    events = same_device_events(5)
    wire_success(monkeypatch, events)
    enriched = []
    monkeypatch.setattr(
        analysis_worker,
        "enrich_pending_windows_4625_ips",
        lambda pending: enriched.extend(pending),
    )

    result = analysis_worker.analyze_once()

    assert result["events_processed"] == 5
    assert enriched == events


def security_log_clear_event():
    record = event(0, 0)
    record["raw_event"] = {
        "EventID": 1102, "Channel": "Security",
        "ProviderName": "Microsoft-Windows-Eventlog",
        "StringInserts": ["S-1-5-18", "operator", "LAB", "0x123"],
    }
    return record


def test_win002_persists_alert_incident_and_marks_only_its_state(monkeypatch):
    record = security_log_clear_event()
    monkeypatch.setattr(
        analysis_worker, "fetch_unprocessed_security_log_clears",
        lambda limit: [record],
    )
    calls = []
    monkeypatch.setattr(
        analysis_worker, "persist_detection",
        lambda candidate: (
            calls.append(("detection", candidate.rule_id))
            or DetectionResult(created=True)
        ),
    )
    monkeypatch.setattr(
        analysis_worker, "create_alert_for_detection",
        lambda detection_id: AlertResult(created=True),
    )
    monkeypatch.setattr(
        analysis_worker, "correlate_alert_to_incident",
        lambda alert_id: IncidentResult(created=True),
    )
    monkeypatch.setattr(
        analysis_worker, "mark_event_analysis_processed",
        lambda event_id, rule_id: calls.append(("processed", rule_id)),
    )
    result = analysis_worker.analyze_security_log_clears_once()
    assert result["events_processed"] == 1
    assert result["detections_created"] == 1
    assert result["alerts_created"] == 1
    assert result["incidents_created"] == 1
    assert result["events_failed"] == 0
    assert calls == [
        ("detection", "RULE-WIN-002"),
        ("processed", "RULE-WIN-002"),
    ]


def test_win002_failure_remains_retryable_and_does_not_touch_win001(monkeypatch):
    record = security_log_clear_event()
    monkeypatch.setattr(
        analysis_worker, "fetch_unprocessed_security_log_clears",
        lambda limit: [record],
    )
    monkeypatch.setattr(
        analysis_worker, "persist_detection",
        lambda candidate: (_ for _ in ()).throw(RuntimeError("db unavailable")),
    )
    failures = []
    monkeypatch.setattr(
        analysis_worker, "mark_event_analysis_failed",
        lambda event_id, error, rule_id: failures.append((error, rule_id)),
    )
    monkeypatch.setattr(
        analysis_worker, "mark_event_analysis_processed",
        lambda *args: pytest.fail("Must not mark failed event processed"),
    )
    result = analysis_worker.analyze_security_log_clears_once()
    assert result["events_failed"] == 1
    assert result["events_processed"] == 0
    assert failures == [("db unavailable", "RULE-WIN-002")]


def test_win002_reused_detection_does_not_create_duplicate_alert(monkeypatch):
    record = security_log_clear_event()
    monkeypatch.setattr(
        analysis_worker, "fetch_unprocessed_security_log_clears",
        lambda limit: [record],
    )
    monkeypatch.setattr(
        analysis_worker, "persist_detection",
        lambda candidate: DetectionResult(created=False),
    )
    monkeypatch.setattr(
        analysis_worker, "create_alert_for_detection",
        lambda detection_id: AlertResult(created=False),
    )
    monkeypatch.setattr(
        analysis_worker, "correlate_alert_to_incident",
        lambda alert_id: IncidentResult(created=False),
    )
    monkeypatch.setattr(
        analysis_worker, "mark_event_analysis_processed",
        lambda event_id, rule_id: None,
    )
    result = analysis_worker.analyze_security_log_clears_once()
    assert result["detections_reused"] == 1
    assert result["alerts_reused"] == 1
    assert result["incidents_reused"] == 1
    assert result["detections_created"] == 0
    assert result["alerts_created"] == 0
    assert result["incidents_created"] == 0


def privileged_group_event():
    record = event(0, 0)
    record["raw_event"] = {
        "EventID": 4732, "Channel": "Security",
        "ProviderName": "Microsoft-Windows-Security-Auditing",
        "StringInserts": [
            "-", "S-1-5-21-1-2-3-1001", "Administrators", "BUILTIN",
            "S-1-5-32-544", "-", "admin", "LAB", "0x123", "-",
        ],
    }
    return record


def test_win003_creates_detection_alert_incident_and_only_its_state(monkeypatch):
    record = privileged_group_event()
    monkeypatch.setattr(
        analysis_worker, "fetch_unprocessed_privileged_group_events",
        lambda limit: [record],
    )
    calls = []
    monkeypatch.setattr(
        analysis_worker, "persist_detection",
        lambda candidate: (
            calls.append(("detection", candidate.rule_id))
            or DetectionResult(created=True)
        ),
    )
    monkeypatch.setattr(
        analysis_worker, "create_alert_for_detection",
        lambda detection_id: AlertResult(created=True),
    )
    monkeypatch.setattr(
        analysis_worker, "correlate_alert_to_incident",
        lambda alert_id: IncidentResult(created=True),
    )
    monkeypatch.setattr(
        analysis_worker, "mark_event_analysis_processed",
        lambda event_id, rule_id: calls.append(("processed", rule_id)),
    )
    result = analysis_worker.analyze_privileged_group_once()
    assert result["events_processed"] == 1
    assert result["detections_created"] == 1
    assert result["alerts_created"] == 1
    assert result["incidents_created"] == 1
    assert result["events_failed"] == 0
    assert calls == [
        ("detection", "RULE-WIN-003"),
        ("processed", "RULE-WIN-003"),
    ]


def test_win003_ordinary_local_group_is_processed_without_alert(monkeypatch):
    record = privileged_group_event()
    record["raw_event"]["StringInserts"][4] = "S-1-5-32-545"
    monkeypatch.setattr(
        analysis_worker, "fetch_unprocessed_privileged_group_events",
        lambda limit: [record],
    )
    monkeypatch.setattr(
        analysis_worker, "persist_detection",
        lambda candidate: pytest.fail("Ordinary group must not create detection"),
    )
    processed = []
    monkeypatch.setattr(
        analysis_worker, "mark_event_analysis_processed",
        lambda event_id, rule_id: processed.append(rule_id),
    )
    result = analysis_worker.analyze_privileged_group_once()
    assert result["events_processed"] == 1
    assert result["detections_created"] == 0
    assert processed == ["RULE-WIN-003"]


def test_win003_failure_is_retryable_without_affecting_win001(monkeypatch):
    record = privileged_group_event()
    monkeypatch.setattr(
        analysis_worker, "fetch_unprocessed_privileged_group_events",
        lambda limit: [record],
    )
    monkeypatch.setattr(
        analysis_worker, "persist_detection",
        lambda candidate: (_ for _ in ()).throw(RuntimeError("database failure")),
    )
    failed = []
    monkeypatch.setattr(
        analysis_worker, "mark_event_analysis_failed",
        lambda event_id, error, rule_id: failed.append((error, rule_id)),
    )
    monkeypatch.setattr(
        analysis_worker, "mark_event_analysis_processed",
        lambda *args: pytest.fail("Failed event must be retried"),
    )
    result = analysis_worker.analyze_privileged_group_once()
    assert result["events_failed"] == 1
    assert result["events_processed"] == 0
    assert failed == [("database failure", "RULE-WIN-003")]


def test_win003_reuses_existing_detection_alert_incident(monkeypatch):
    record = privileged_group_event()
    monkeypatch.setattr(
        analysis_worker, "fetch_unprocessed_privileged_group_events",
        lambda limit: [record],
    )
    monkeypatch.setattr(
        analysis_worker, "persist_detection",
        lambda candidate: DetectionResult(created=False),
    )
    monkeypatch.setattr(
        analysis_worker, "create_alert_for_detection",
        lambda detection_id: AlertResult(created=False),
    )
    monkeypatch.setattr(
        analysis_worker, "correlate_alert_to_incident",
        lambda alert_id: IncidentResult(created=False),
    )
    monkeypatch.setattr(
        analysis_worker, "mark_event_analysis_processed",
        lambda event_id, rule_id: None,
    )
    result = analysis_worker.analyze_privileged_group_once()
    assert result["detections_reused"] == 1
    assert result["alerts_reused"] == 1
    assert result["incidents_reused"] == 1
    assert result["detections_created"] == 0
    assert result["alerts_created"] == 0
    assert result["incidents_created"] == 0


def account_change_event(event_id=4720):
    record = event(0, 0)
    record["raw_event"] = {
        "EventID": event_id,
        "Channel": "Security",
        "ProviderName": "Microsoft-Windows-Security-Auditing",
        "StringInserts": [
            "newuser", "LAB", "S-1-5-21-1-2-3-1005",
            "S-1-5-21-1-2-3-500", "administrator", "LAB",
            "0x123",
        ],
    }
    return record


@pytest.mark.parametrize("event_id", [4720, 4722])
def test_win004_persists_detection_alert_incident_with_isolated_state(monkeypatch, event_id):
    record = account_change_event(event_id)
    monkeypatch.setattr(
        analysis_worker, "fetch_unprocessed_account_lifecycle_events",
        lambda limit: [record],
    )
    captured = []
    monkeypatch.setattr(
        analysis_worker, "persist_detection",
        lambda candidate: (
            captured.append(("detection", candidate.rule_id, candidate.target_user))
            or DetectionResult(created=True)
        ),
    )
    monkeypatch.setattr(
        analysis_worker, "create_alert_for_detection",
        lambda detection_id: AlertResult(created=True),
    )
    monkeypatch.setattr(
        analysis_worker, "correlate_alert_to_incident",
        lambda alert_id: IncidentResult(created=True),
    )
    monkeypatch.setattr(
        analysis_worker, "mark_event_analysis_processed",
        lambda event_id, rule_id: captured.append(("processed", rule_id)),
    )
    result = analysis_worker.analyze_account_lifecycle_once()
    assert result["events_processed"] == 1
    assert result["detections_created"] == 1
    assert result["alerts_created"] == 1
    assert result["incidents_created"] == 1
    assert result["events_failed"] == 0
    assert captured == [
        ("detection", "RULE-WIN-004", "LAB\\newuser"),
        ("processed", "RULE-WIN-004"),
    ]


def test_win004_retry_marks_only_its_own_event_state(monkeypatch):
    record = account_change_event()
    monkeypatch.setattr(
        analysis_worker, "fetch_unprocessed_account_lifecycle_events",
        lambda limit: [record],
    )
    monkeypatch.setattr(
        analysis_worker, "persist_detection",
        lambda candidate: (_ for _ in ()).throw(RuntimeError("db unavailable")),
    )
    failures = []
    monkeypatch.setattr(
        analysis_worker, "mark_event_analysis_failed",
        lambda event_id, error, rule_id: failures.append((error, rule_id)),
    )
    monkeypatch.setattr(
        analysis_worker, "mark_event_analysis_processed",
        lambda *args: pytest.fail("Must not mark failed event processed"),
    )
    result = analysis_worker.analyze_account_lifecycle_once()
    assert result["events_failed"] == 1
    assert result["events_processed"] == 0
    assert failures == [("db unavailable", "RULE-WIN-004")]


def test_win004_reuses_detection_alert_incident_on_retry(monkeypatch):
    record = account_change_event(4722)
    monkeypatch.setattr(
        analysis_worker, "fetch_unprocessed_account_lifecycle_events",
        lambda limit: [record],
    )
    monkeypatch.setattr(
        analysis_worker, "persist_detection",
        lambda candidate: DetectionResult(created=False),
    )
    monkeypatch.setattr(
        analysis_worker, "create_alert_for_detection",
        lambda detection_id: AlertResult(created=False),
    )
    monkeypatch.setattr(
        analysis_worker, "correlate_alert_to_incident",
        lambda alert_id: IncidentResult(created=False),
    )
    monkeypatch.setattr(
        analysis_worker, "mark_event_analysis_processed",
        lambda event_id, rule_id: None,
    )
    result = analysis_worker.analyze_account_lifecycle_once()
    assert result["detections_reused"] == 1
    assert result["alerts_reused"] == 1
    assert result["incidents_reused"] == 1
    assert result["detections_created"] == 0
    assert result["alerts_created"] == 0
    assert result["incidents_created"] == 0


def test_win004_no_pending_events_is_noop(monkeypatch):
    monkeypatch.setattr(
        analysis_worker, "fetch_unprocessed_account_lifecycle_events",
        lambda limit: [],
    )
    result = analysis_worker.analyze_account_lifecycle_once()
    assert result["events_processed"] == 0
    assert result["events_failed"] == 0
