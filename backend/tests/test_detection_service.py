from datetime import datetime, timezone
from dataclasses import replace

import pytest
from unittest.mock import MagicMock
from uuid import UUID, uuid4

from app.analysis.failed_login_rule import (
    FailedLoginDetectionCandidate,
)
from app.analysis.detection_candidate import DetectionCandidate
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

    assert "event_rule_analysis_state" in sql
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

    assert "event_rule_analysis_state" in sql
    assert "failed" in sql
    assert params == (event_id, "RULE-WIN-001", "bad evidence")


def test_per_rule_completed_state_is_scoped(monkeypatch):
    cursor = MagicMock()
    monkeypatch.setattr(
        detection_service.psycopg, "connect",
        lambda **kwargs: connection_with_cursor(cursor),
    )
    event_id = uuid4()
    detection_service.mark_event_analysis_processed(event_id, "RULE-WIN-009")
    sql, params = cursor.execute.call_args.args
    assert "ON CONFLICT (event_id, rule_id)" in sql
    assert params == (event_id, "RULE-WIN-009")


def test_per_rule_failure_is_scoped(monkeypatch):
    cursor = MagicMock()
    monkeypatch.setattr(
        detection_service.psycopg, "connect",
        lambda **kwargs: connection_with_cursor(cursor),
    )
    event_id = uuid4()
    detection_service.mark_event_analysis_failed(
        event_id, "simulated error", "RULE-LIN-001"
    )
    sql, params = cursor.execute.call_args.args
    assert "ON CONFLICT (event_id, rule_id)" in sql
    assert params == (event_id, "RULE-LIN-001", "simulated error")


def general_candidate():
    old = candidate()
    return DetectionCandidate(
        rule_id="RULE-WIN-002",
        rule_name="Security Log Cleared",
        severity="high",
        device_id=old.device_id,
        grouping_basis="device_event",
        event_ids=(old.event_ids[0],),
        event_count=1,
        window_start=old.window_start,
        window_end=old.window_start,
    )


def test_generic_candidate_with_missing_user_and_ip_persists(monkeypatch):
    item = general_candidate()
    cursor = MagicMock()
    detection_id = uuid4()
    cursor.fetchone.return_value = (detection_id,)
    monkeypatch.setattr(
        detection_service.psycopg,
        "connect",
        lambda **kwargs: connection_with_cursor(cursor),
    )

    result = detection_service.persist_detection(item)

    assert result.created is True
    assert result.detection_id == detection_id
    sql, params = cursor.execute.call_args_list[0].args
    assert "INSERT INTO detections" in sql
    assert params[6] is None  # no invented target user
    assert params[7] is None  # no invented source IP
    assert params[8] is None  # no invented logon type
    assert params[9] == "device_event"
    assert len([call for call in cursor.execute.call_args_list
                if "INSERT INTO detection_events" in call.args[0]]) == 1


def test_generic_candidate_fingerprint_stable_and_rule_scoped():
    item = general_candidate()
    fp = detection_service.build_detection_fingerprint(item)
    assert fp == detection_service.build_detection_fingerprint(item)
    assert fp != detection_service.build_detection_fingerprint(
        replace(item, rule_id="RULE-WIN-003")
    )


@pytest.mark.parametrize("changes", [
    {"event_ids": ()},
    {"event_ids": ("same", "same"), "event_count": 2},
    {"event_count": 2},
    {"severity": "unknown"},
    {"rule_id": ""},
    {"window_end": datetime(2026, 11, 9, 5, 49, tzinfo=timezone.utc)},
    {"window_start": datetime(2026, 11, 9, 5, 50)},
])
def test_invalid_generic_candidate_rejected_before_database(changes, monkeypatch):
    monkeypatch.setattr(
        detection_service.psycopg, "connect",
        lambda **kwargs: pytest.fail("Database must not be contacted"),
    )
    with pytest.raises(ValueError):
        detection_service.persist_detection(replace(general_candidate(), **changes))


def test_win001_fingerprint_matches_previous_algorithm():
    import hashlib
    item = candidate()
    material = "|".join((
        item.rule_id, item.device_id,
        item.target_user.casefold(), item.source_ip or "",
        str(item.logon_type or ""), item.grouping_basis,
        item.window_start.isoformat(), item.window_end.isoformat(),
        "|".join(sorted(item.event_ids)),
    ))
    assert detection_service.build_detection_fingerprint(item) == (
        hashlib.sha256(material.encode("utf-8")).hexdigest()
    )
