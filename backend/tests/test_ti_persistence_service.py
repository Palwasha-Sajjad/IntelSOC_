import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from app.services import ti_persistence_service
from app.services.ti_provider_result import ProviderResult


def connection_with_cursor(cursor):
    connection = MagicMock()
    connection.cursor.return_value.__enter__.return_value = cursor

    context = MagicMock()
    context.__enter__.return_value = connection
    context.__exit__.return_value = False

    return context


def test_get_alert_evidence_uses_detection_links(monkeypatch):
    alert_id = uuid4()
    detection_id = uuid4()
    event_id = uuid4()

    cursor = MagicMock()
    cursor.fetchall.return_value = [
        (
            alert_id,
            detection_id,
            event_id,
            "windows_eventlog",
            {"EventID": 4625},
        )
    ]

    monkeypatch.setattr(
        ti_persistence_service.psycopg,
        "connect",
        lambda **kwargs: connection_with_cursor(cursor),
    )

    evidence = ti_persistence_service.get_alert_evidence(alert_id)

    assert len(evidence) == 1
    assert evidence[0].alert_id == alert_id
    assert evidence[0].detection_id == detection_id
    assert evidence[0].event_id == event_id
    assert evidence[0].raw_event == {"EventID": 4625}

    sql, params = cursor.execute.call_args.args
    assert "JOIN detection_events AS de" in sql
    assert "JOIN security_events AS e" in sql
    assert params == (alert_id,)


def test_get_cached_ti_result_returns_only_nonexpired(monkeypatch):
    result_id = uuid4()
    now = datetime(2026, 11, 10, tzinfo=timezone.utc)
    expires = now + timedelta(hours=24)

    cursor = MagicMock()
    cursor.fetchone.return_value = (
        result_id,
        "virustotal",
        "ip",
        "8.8.8.8",
        "benign",
        "success",
        80,
        {"analysis_stats": {"harmless": 4}},
        now,
        expires,
    )

    monkeypatch.setattr(
        ti_persistence_service.psycopg,
        "connect",
        lambda **kwargs: connection_with_cursor(cursor),
    )

    cached = ti_persistence_service.get_cached_ti_result(
        "virustotal",
        "ip",
        "8.8.8.8",
        now=now,
    )

    assert cached is not None
    assert cached.result_id == result_id
    assert cached.expires_at == expires

    sql, params = cursor.execute.call_args.args
    assert "expires_at > %s" in sql
    assert params == ("virustotal", "ip", "8.8.8.8", now)


def test_get_cached_ti_result_returns_none_on_miss(monkeypatch):
    cursor = MagicMock()
    cursor.fetchone.return_value = None

    monkeypatch.setattr(
        ti_persistence_service.psycopg,
        "connect",
        lambda **kwargs: connection_with_cursor(cursor),
    )

    assert ti_persistence_service.get_cached_ti_result(
        "virustotal",
        "domain",
        "example.org",
    ) is None


def test_persist_ti_result_upserts_cache(monkeypatch):
    returned_id = uuid4()
    cursor = MagicMock()
    cursor.fetchone.return_value = (returned_id,)

    monkeypatch.setattr(
        ti_persistence_service.psycopg,
        "connect",
        lambda **kwargs: connection_with_cursor(cursor),
    )

    checked = datetime(2026, 11, 10, tzinfo=timezone.utc)
    expires = checked + timedelta(hours=24)

    result = ProviderResult(
        provider="virustotal",
        indicator_type="ip",
        indicator_value="8.8.8.8",
        verdict="benign",
        lookup_status="success",
        confidence=75,
        details={"analysis_stats": {"harmless": 3}},
    )

    result_id = ti_persistence_service.persist_ti_result(
        result,
        checked_at=checked,
        expires_at=expires,
    )

    assert result_id == returned_id

    sql, params = cursor.execute.call_args.args
    assert "INSERT INTO ti_results" in sql
    assert "ON CONFLICT" in sql
    assert "DO UPDATE SET" in sql
    assert json.loads(params[7]) == result.details
    assert params[8] == checked
    assert params[9] == expires


def test_persist_ti_result_validates_timestamps_before_db(monkeypatch):
    monkeypatch.setattr(
        ti_persistence_service.psycopg,
        "connect",
        lambda **kwargs: pytest.fail("Database must not be contacted"),
    )

    result = ProviderResult(
        provider="virustotal",
        indicator_type="ip",
        indicator_value="8.8.8.8",
        verdict="unknown",
        lookup_status="error",
    )

    checked = datetime(2026, 11, 10)

    with pytest.raises(ValueError, match="timezone-aware"):
        ti_persistence_service.persist_ti_result(
            result,
            checked_at=checked,
            expires_at=checked + timedelta(hours=1),
        )


def test_link_alert_indicator_is_idempotent(monkeypatch):
    cursor = MagicMock()

    monkeypatch.setattr(
        ti_persistence_service.psycopg,
        "connect",
        lambda **kwargs: connection_with_cursor(cursor),
    )

    alert_id = uuid4()
    event_id = uuid4()
    result_id = uuid4()

    ti_persistence_service.link_alert_indicator(
        alert_id=alert_id,
        event_id=event_id,
        result_id=result_id,
    )

    sql, params = cursor.execute.call_args.args
    assert "INSERT INTO alert_ti_indicators" in sql
    assert "ON CONFLICT DO NOTHING" in sql
    assert params == (alert_id, event_id, result_id)


def test_mark_alert_ti_processed_upserts_state(monkeypatch):
    cursor = MagicMock()

    monkeypatch.setattr(
        ti_persistence_service.psycopg,
        "connect",
        lambda **kwargs: connection_with_cursor(cursor),
    )

    alert_id = uuid4()

    ti_persistence_service.mark_alert_ti_processed(alert_id)

    sql, params = cursor.execute.call_args.args
    assert "alert_ti_analysis_state" in sql
    assert "attempts = alert_ti_analysis_state.attempts + 1" in sql
    assert params == (alert_id, "processed", None, "processed")


def test_mark_alert_ti_failed_records_error(monkeypatch):
    cursor = MagicMock()

    monkeypatch.setattr(
        ti_persistence_service.psycopg,
        "connect",
        lambda **kwargs: connection_with_cursor(cursor),
    )

    alert_id = uuid4()

    ti_persistence_service.mark_alert_ti_failed(
        alert_id,
        "provider timeout",
    )

    sql, params = cursor.execute.call_args.args
    assert "alert_ti_analysis_state" in sql
    assert params == (
        alert_id,
        "failed",
        "provider timeout",
        "failed",
    )
