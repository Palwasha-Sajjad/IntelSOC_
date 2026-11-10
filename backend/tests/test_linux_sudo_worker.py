from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID

import pytest

from app.workers import analysis_worker


NOW = datetime(2026, 11, 10, 16, 0, tzinfo=timezone.utc)


def sudo_event(message, *, src_ip=None, raw_ip=None):
    raw = {
        "_COMM": "sudo",
        "SYSLOG_IDENTIFIER": "sudo",
        "MESSAGE": message,
    }
    if raw_ip is not None:
        raw["_REMOTE_ADDR"] = raw_ip
    return {
        "event_id": "00000000-0000-0000-0000-000000000301",
        "device_id": "linux-device-1",
        "event_time": NOW,
        "src_ip": src_ip,
        "message": message,
        "raw_event": raw,
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


def test_lin005_worker_persists_suspicious_remote_sudo(monkeypatch):
    pending = [sudo_event(
        "socadmin : TTY=pts/0 ; PWD=/home/socadmin ; "
        "USER=root ; COMMAND=/usr/bin/id",
        src_ip="198.51.100.77",
        raw_ip="198.51.100.77",
    )]
    monkeypatch.setattr(
        analysis_worker, "fetch_unprocessed_linux_sudo_events",
        lambda limit: pending,
    )
    calls = []
    monkeypatch.setattr(
        analysis_worker, "persist_detection",
        lambda candidate: (
            calls.append(("detection", candidate.rule_id)) or DetectionResult()
        ),
    )
    monkeypatch.setattr(
        analysis_worker, "create_alert_for_detection",
        lambda detection_id: AlertResult(),
    )
    monkeypatch.setattr(
        analysis_worker, "correlate_alert_to_incident",
        lambda alert_id: IncidentResult(),
    )
    monkeypatch.setattr(
        analysis_worker, "mark_event_analysis_processed",
        lambda event_id, rule_id: calls.append(("processed", rule_id)),
    )

    result = analysis_worker.analyze_linux_sudo_once()
    assert result["events_processed"] == 1
    assert result["detections_created"] == 1
    assert result["alerts_created"] == 1
    assert result["incidents_created"] == 1
    assert calls == [
        ("detection", "RULE-LIN-005"),
        ("processed", "RULE-LIN-005"),
    ]


def test_lin005_worker_marks_benign_local_sudo_processed(monkeypatch):
    pending = [sudo_event(
        "socadmin : TTY=pts/0 ; PWD=/home/socadmin ; "
        "USER=root ; COMMAND=/usr/bin/id"
    )]
    monkeypatch.setattr(
        analysis_worker, "fetch_unprocessed_linux_sudo_events",
        lambda limit: pending,
    )
    monkeypatch.setattr(
        analysis_worker, "persist_detection",
        lambda candidate: pytest.fail("Local sudo must remain benign"),
    )
    processed = []
    monkeypatch.setattr(
        analysis_worker, "mark_event_analysis_processed",
        lambda event_id, rule_id: processed.append(rule_id),
    )

    result = analysis_worker.analyze_linux_sudo_once()
    assert result["events_processed"] == 1
    assert result["detections_created"] == 0
    assert processed == ["RULE-LIN-005"]


def test_lin005_worker_failure_is_retryable(monkeypatch):
    pending = [sudo_event(
        "guest : user NOT in sudoers ; TTY=pts/0 ; "
        "PWD=/home/guest ; USER=root ; COMMAND=/usr/bin/id"
    )]
    monkeypatch.setattr(
        analysis_worker, "fetch_unprocessed_linux_sudo_events",
        lambda limit: pending,
    )
    monkeypatch.setattr(
        analysis_worker, "persist_detection",
        lambda candidate: (_ for _ in ()).throw(
            RuntimeError("database unavailable")
        ),
    )
    failed = []
    monkeypatch.setattr(
        analysis_worker, "mark_event_analysis_failed",
        lambda event_id, error, rule_id: failed.append((error, rule_id)),
    )
    monkeypatch.setattr(
        analysis_worker, "mark_event_analysis_processed",
        lambda *args: pytest.fail("Failed event must stay retryable"),
    )

    with pytest.raises(RuntimeError, match="database unavailable"):
        analysis_worker.analyze_linux_sudo_once()

    assert failed == [("database unavailable", "RULE-LIN-005")]


def test_lin005_worker_reuses_artifacts_on_retry(monkeypatch):
    pending = [sudo_event(
        "guest : user NOT in sudoers ; TTY=pts/0 ; "
        "PWD=/home/guest ; USER=root ; COMMAND=/usr/bin/id"
    )]
    monkeypatch.setattr(
        analysis_worker, "fetch_unprocessed_linux_sudo_events",
        lambda limit: pending,
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

    result = analysis_worker.analyze_linux_sudo_once()
    assert result["detections_reused"] == 1
    assert result["alerts_reused"] == 1
    assert result["incidents_reused"] == 1


def test_lin005_worker_no_pending_is_noop(monkeypatch):
    monkeypatch.setattr(
        analysis_worker, "fetch_unprocessed_linux_sudo_events",
        lambda limit: [],
    )
    result = analysis_worker.analyze_linux_sudo_once()
    assert result["events_processed"] == 0
    assert result["events_failed"] == 0
