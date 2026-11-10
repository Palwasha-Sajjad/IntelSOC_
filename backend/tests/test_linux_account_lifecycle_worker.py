from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID

import pytest

from app.workers import analysis_worker


NOW = datetime(2026, 11, 10, 18, 20, tzinfo=timezone.utc)


def audit_event(raw_line):
    return {
        "event_id": "00000000-0000-0000-0000-000000000351",
        "device_id": "linux-device-1",
        "event_time": NOW,
        "src_ip": None,
        "message": raw_line,
        "raw_event": {"log": raw_line},
        "event_type": "linux_account_audit_event",
    }


@dataclass
class DetectionResult:
    detection_id: UUID = UUID("10000000-0000-0000-0000-000000000003")
    created: bool = True


@dataclass
class AlertResult:
    alert_id: UUID = UUID("20000000-0000-0000-0000-000000000003")
    created: bool = True


@dataclass
class IncidentResult:
    created: bool = True


def test_lin003_worker_persists_account_change(monkeypatch):
    pending = [audit_event(
        'type=ADD_USER msg=audit(1794334800.123:700): '
        'acct="newuser" res=success'
    )]
    monkeypatch.setattr(
        analysis_worker,
        "fetch_unprocessed_linux_account_events",
        lambda limit: pending,
    )

    calls = []
    monkeypatch.setattr(
        analysis_worker,
        "persist_detection",
        lambda candidate: (
            calls.append(("detection", candidate.rule_id))
            or DetectionResult()
        ),
    )
    monkeypatch.setattr(
        analysis_worker,
        "create_alert_for_detection",
        lambda detection_id: AlertResult(),
    )
    monkeypatch.setattr(
        analysis_worker,
        "correlate_alert_to_incident",
        lambda alert_id: IncidentResult(),
    )
    monkeypatch.setattr(
        analysis_worker,
        "mark_event_analysis_processed",
        lambda event_id, rule_id: calls.append(("processed", rule_id)),
    )

    result = analysis_worker.analyze_linux_account_lifecycle_once()

    assert result["events_processed"] == 1
    assert result["detections_created"] == 1
    assert result["alerts_created"] == 1
    assert result["incidents_created"] == 1
    assert calls == [
        ("detection", "RULE-LIN-003"),
        ("processed", "RULE-LIN-003"),
    ]


def test_lin003_worker_benign_group_semantics_are_processed(monkeypatch):
    pending = [audit_event(
        'type=USER_MGMT msg=audit(1794334800.123:701): '
        'acct="alice" grp="developers" res=success'
    )]
    monkeypatch.setattr(
        analysis_worker,
        "fetch_unprocessed_linux_account_events",
        lambda limit: pending,
    )
    monkeypatch.setattr(
        analysis_worker,
        "persist_detection",
        lambda candidate: pytest.fail("group semantics belong to LIN-004"),
    )

    processed = []
    monkeypatch.setattr(
        analysis_worker,
        "mark_event_analysis_processed",
        lambda event_id, rule_id: processed.append(rule_id),
    )

    result = analysis_worker.analyze_linux_account_lifecycle_once()

    assert result["events_processed"] == 1
    assert result["detections_created"] == 0
    assert processed == ["RULE-LIN-003"]


def test_lin003_worker_failure_is_retryable(monkeypatch):
    pending = [audit_event(
        'type=DEL_USER msg=audit(1794334800.123:702): '
        'acct="olduser" res=success'
    )]
    monkeypatch.setattr(
        analysis_worker,
        "fetch_unprocessed_linux_account_events",
        lambda limit: pending,
    )
    monkeypatch.setattr(
        analysis_worker,
        "persist_detection",
        lambda candidate: (_ for _ in ()).throw(
            RuntimeError("database unavailable")
        ),
    )

    failed = []
    monkeypatch.setattr(
        analysis_worker,
        "mark_event_analysis_failed",
        lambda event_id, error, rule_id: failed.append((error, rule_id)),
    )
    monkeypatch.setattr(
        analysis_worker,
        "mark_event_analysis_processed",
        lambda *args: pytest.fail("failed event must remain retryable"),
    )

    with pytest.raises(RuntimeError, match="database unavailable"):
        analysis_worker.analyze_linux_account_lifecycle_once()

    assert failed == [("database unavailable", "RULE-LIN-003")]


def test_lin003_worker_reuses_existing_artifacts(monkeypatch):
    pending = [audit_event(
        'type=USER_MGMT msg=audit(1794334800.123:703): '
        'acct="alice" res=success'
    )]
    monkeypatch.setattr(
        analysis_worker,
        "fetch_unprocessed_linux_account_events",
        lambda limit: pending,
    )
    monkeypatch.setattr(
        analysis_worker,
        "persist_detection",
        lambda candidate: DetectionResult(created=False),
    )
    monkeypatch.setattr(
        analysis_worker,
        "create_alert_for_detection",
        lambda detection_id: AlertResult(created=False),
    )
    monkeypatch.setattr(
        analysis_worker,
        "correlate_alert_to_incident",
        lambda alert_id: IncidentResult(created=False),
    )
    monkeypatch.setattr(
        analysis_worker,
        "mark_event_analysis_processed",
        lambda event_id, rule_id: None,
    )

    result = analysis_worker.analyze_linux_account_lifecycle_once()

    assert result["detections_reused"] == 1
    assert result["alerts_reused"] == 1
    assert result["incidents_reused"] == 1


def test_lin003_worker_no_pending_is_noop(monkeypatch):
    monkeypatch.setattr(
        analysis_worker,
        "fetch_unprocessed_linux_account_events",
        lambda limit: [],
    )
    result = analysis_worker.analyze_linux_account_lifecycle_once()
    assert result["events_processed"] == 0
    assert result["events_failed"] == 0
