from datetime import datetime, timezone
from unittest.mock import MagicMock
from uuid import UUID, uuid4

from app.analysis.failed_login_rule import (
    FailedLoginDetectionCandidate,
)
from app.services import detection_service


def candidate():
    return FailedLoginDetectionCandidate(
        rule_id="RULE-WIN-001",
        rule_name="Repeated Failed Logins",
        severity="medium",
        device_id=str(uuid4()),
        target_user="PMYLS",
        source_ip=None,
        logon_type=2,
        grouping_basis="device_user_logon_type",
        event_ids=(
            str(uuid4()),
            str(uuid4()),
            str(uuid4()),
            str(uuid4()),
            str(uuid4()),
        ),
        event_count=5,
        window_start=datetime(
            2026,
            11,
            9,
            5,
            50,
            0,
            tzinfo=timezone.utc,
        ),
        window_end=datetime(
            2026,
            11,
            9,
            5,
            52,
            0,
            tzinfo=timezone.utc,
        ),
    )


def connection_with_cursor(cursor):
    connection = MagicMock()
    connection.cursor.return_value.__enter__.return_value = cursor

    context = MagicMock()
    context.__enter__.return_value = connection
    context.__exit__.return_value = False

    return context


def test_detection_fingerprint_is_stable():
    item = candidate()

    first = detection_service.build_detection_fingerprint(item)
    second = detection_service.build_detection_fingerprint(item)

    assert first == second
    assert len(first) == 64


def test_detection_fingerprint_changes_when_evidence_changes():
    first = candidate()

    second = FailedLoginDetectionCandidate(
        **{
            **first.__dict__,
            "event_ids": (
                *first.event_ids[:-1],
                str(uuid4()),
            ),
        }
    )

    assert (
        detection_service.build_detection_fingerprint(first)
        != detection_service.build_detection_fingerprint(second)
    )


def test_persist_detection_creates_new_detection_and_links(monkeypatch):
    item = candidate()
    detection_id = uuid4()

    cursor = MagicMock()
    cursor.fetchone.side_effect = [
        (detection_id,),
    ]

    monkeypatch.setattr(
        detection_service.psycopg,
        "connect",
        lambda **kwargs: connection_with_cursor(cursor),
    )

    result = detection_service.persist_detection(item)

    assert result.detection_id == detection_id
    assert result.created is True

    sql_calls = [
        call.args[0]
        for call in cursor.execute.call_args_list
    ]

    assert any(
        "INSERT INTO detections" in sql
        for sql in sql_calls
    )

    link_calls = [
        call
        for call in cursor.execute.call_args_list
        if "INSERT INTO detection_events" in call.args[0]
    ]

    assert len(link_calls) == 5


def test_persist_detection_reuses_existing_fingerprint(monkeypatch):
    item = candidate()
    existing_id = uuid4()

    cursor = MagicMock()
    cursor.fetchone.side_effect = [
        None,
        (existing_id,),
    ]

    monkeypatch.setattr(
        detection_service.psycopg,
        "connect",
        lambda **kwargs: connection_with_cursor(cursor),
    )

    result = detection_service.persist_detection(item)

    assert result.detection_id == existing_id
    assert result.created is False


def test_mark_processed_upserts_state(monkeypatch):
    cursor = MagicMock()

    monkeypatch.setattr(
        detection_service.psycopg,
        "connect",
        lambda **kwargs: connection_with_cursor(cursor),
    )

    event_id = UUID(str(uuid4()))

    detection_service.mark_event_analysis_processed(
        event_id
    )

    sql = cursor.execute.call_args.args[0]

    assert "event_analysis_state" in sql
    assert "processed" in sql


def test_mark_failed_upserts_state_and_error(monkeypatch):
    cursor = MagicMock()

    monkeypatch.setattr(
        detection_service.psycopg,
        "connect",
        lambda **kwargs: connection_with_cursor(cursor),
    )

    event_id = UUID(str(uuid4()))

    detection_service.mark_event_analysis_failed(
        event_id,
        "bad evidence",
    )

    sql, params = cursor.execute.call_args.args

    assert "event_analysis_state" in sql
    assert "failed" in sql
    assert params[1] == "bad evidence"
