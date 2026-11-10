from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest

from app.workers import analysis_worker


BASE = datetime(2026, 11, 10, 10, 0, tzinfo=timezone.utc)


def ssh_event(index: int, *, success: bool = False):
    source_ip = "192.0.2.25"
    outcome = "Accepted" if success else "Failed"
    message = (
        f"{outcome} password for alice from {source_ip} "
        f"port {40000 + index} ssh2"
    )
    return {
        "event_id": f"00000000-0000-0000-0002-{index:012d}",
        "device_id": "linux-device-1",
        "event_time": BASE + timedelta(seconds=index * 30),
        "src_ip": source_ip,
        "message": message,
        "raw_event": {
            "_SYSTEMD_UNIT": "ssh.service",
            "MESSAGE": message,
        },
    }


@dataclass
class DetectionResult:
    detection_id: UUID = UUID("30000000-0000-0000-0000-000000000001")
    created: bool = True


@dataclass
class AlertResult:
    alert_id: UUID = UUID("40000000-0000-0000-0000-000000000001")
    created: bool = True


@dataclass
class IncidentResult:
    created: bool = True


def test_lin002_worker_creates_detection_alert_incident_and_marks_success_state(
    monkeypatch,
):
    history = [ssh_event(index) for index in range(5)]
    success = ssh_event(5, success=True)
    history.append(success)

    monkeypatch.setattr(
        analysis_worker,
        "fetch_unprocessed_linux_ssh_successes",
        lambda limit: [success],
    )
    monkeypatch.setattr(
        analysis_worker,
        "fetch_linux_ssh_auth_history",
        lambda **kwargs: history,
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

    result = analysis_worker.analyze_linux_ssh_auth_correlation_once()

    assert result["events_processed"] == 1
    assert result["detections_created"] == 1
    assert result["alerts_created"] == 1
    assert result["incidents_created"] == 1
    assert result["events_failed"] == 0
    assert calls == [
        ("detection", "RULE-LIN-002"),
        ("processed", "RULE-LIN-002"),
    ]


def test_lin002_worker_below_threshold_marks_success_processed_without_alert(
    monkeypatch,
):
    history = [ssh_event(index) for index in range(4)]
    success = ssh_event(5, success=True)
    history.append(success)

    monkeypatch.setattr(
        analysis_worker,
        "fetch_unprocessed_linux_ssh_successes",
        lambda limit: [success],
    )
    monkeypatch.setattr(
        analysis_worker,
        "fetch_linux_ssh_auth_history",
        lambda **kwargs: history,
    )
    monkeypatch.setattr(
        analysis_worker,
        "persist_detection",
        lambda candidate: pytest.fail("Below threshold must not persist"),
    )

    processed = []
    monkeypatch.setattr(
        analysis_worker,
        "mark_event_analysis_processed",
        lambda event_id, rule_id: processed.append(rule_id),
    )

    result = analysis_worker.analyze_linux_ssh_auth_correlation_once()

    assert result["events_processed"] == 1
    assert result["detections_created"] == 0
    assert processed == ["RULE-LIN-002"]


def test_lin002_worker_failure_remains_retryable_in_own_state(monkeypatch):
    history = [ssh_event(index) for index in range(5)]
    success = ssh_event(5, success=True)
    history.append(success)

    monkeypatch.setattr(
        analysis_worker,
        "fetch_unprocessed_linux_ssh_successes",
        lambda limit: [success],
    )
    monkeypatch.setattr(
        analysis_worker,
        "fetch_linux_ssh_auth_history",
        lambda **kwargs: history,
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
        lambda *args: pytest.fail("Failed success event must stay retryable"),
    )

    with pytest.raises(RuntimeError, match="database unavailable"):
        analysis_worker.analyze_linux_ssh_auth_correlation_once()

    assert failed == [("database unavailable", "RULE-LIN-002")]


def test_lin002_worker_reuses_persisted_artifacts_on_retry(monkeypatch):
    history = [ssh_event(index) for index in range(5)]
    success = ssh_event(5, success=True)
    history.append(success)

    monkeypatch.setattr(
        analysis_worker,
        "fetch_unprocessed_linux_ssh_successes",
        lambda limit: [success],
    )
    monkeypatch.setattr(
        analysis_worker,
        "fetch_linux_ssh_auth_history",
        lambda **kwargs: history,
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

    result = analysis_worker.analyze_linux_ssh_auth_correlation_once()

    assert result["detections_reused"] == 1
    assert result["alerts_reused"] == 1
    assert result["incidents_reused"] == 1
    assert result["detections_created"] == 0
    assert result["alerts_created"] == 0
    assert result["incidents_created"] == 0


def test_lin002_worker_no_pending_success_is_noop(monkeypatch):
    monkeypatch.setattr(
        analysis_worker,
        "fetch_unprocessed_linux_ssh_successes",
        lambda limit: [],
    )

    result = analysis_worker.analyze_linux_ssh_auth_correlation_once()

    assert result["events_processed"] == 0
    assert result["events_failed"] == 0
