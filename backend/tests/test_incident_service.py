from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from app.services import incident_service


NOW = datetime(
    2026,
    11,
    9,
    10,
    30,
    tzinfo=timezone.utc,
)


def connection_with_cursor(cursor):
    connection = MagicMock()
    connection.cursor.return_value.__enter__.return_value = cursor

    context = MagicMock()
    context.__enter__.return_value = connection
    context.__exit__.return_value = False

    return context


def alert_row(
    *,
    alert_id,
    severity="medium",
    source_ip=None,
):
    return (
        alert_id,
        "RULE-WIN-001",
        "Repeated Failed Logins",
        severity,
        uuid4(),
        "PMYLS",
        source_ip,
        NOW,
    )


def test_correlation_key_is_stable_and_entity_sensitive():
    device_id = uuid4()

    first = incident_service.build_incident_correlation_key(
        device_id=device_id,
        target_user="PMYLS",
        source_ip=None,
    )
    second = incident_service.build_incident_correlation_key(
        device_id=device_id,
        target_user="pmyls",
        source_ip=None,
    )
    remote = incident_service.build_incident_correlation_key(
        device_id=device_id,
        target_user="PMYLS",
        source_ip="192.0.2.50",
    )

    assert first == second
    assert first != remote
    assert len(first) == 64


def test_existing_alert_link_is_reused(monkeypatch):
    alert_id = uuid4()
    incident_id = uuid4()

    cursor = MagicMock()
    cursor.fetchone.return_value = (incident_id,)

    monkeypatch.setattr(
        incident_service.psycopg,
        "connect",
        lambda **kwargs: connection_with_cursor(cursor),
    )

    result = incident_service.correlate_alert_to_incident(
        alert_id
    )

    assert result.incident_id == incident_id
    assert result.created is False
    assert result.linked is False


def test_new_alert_creates_incident_and_link(monkeypatch):
    alert_id = uuid4()

    cursor = MagicMock()
    cursor.fetchone.side_effect = [
        None,
        alert_row(alert_id=alert_id),
        None,
        (alert_id,),
    ]

    monkeypatch.setattr(
        incident_service.psycopg,
        "connect",
        lambda **kwargs: connection_with_cursor(cursor),
    )

    result = incident_service.correlate_alert_to_incident(
        alert_id
    )

    assert result.alert_id == alert_id
    assert result.created is True
    assert result.linked is True

    sql_calls = [
        call.args[0]
        for call in cursor.execute.call_args_list
    ]

    assert any(
        "INSERT INTO incidents" in sql
        for sql in sql_calls
    )
    assert any(
        "INSERT INTO incident_alerts" in sql
        for sql in sql_calls
    )
    assert any(
        "INSERT INTO incident_history" in sql
        for sql in sql_calls
    )


def test_recent_matching_incident_is_reused(monkeypatch):
    alert_id = uuid4()
    incident_id = uuid4()

    cursor = MagicMock()
    cursor.fetchone.side_effect = [
        None,
        alert_row(alert_id=alert_id),
        (incident_id, "medium"),
        (alert_id,),
    ]

    monkeypatch.setattr(
        incident_service.psycopg,
        "connect",
        lambda **kwargs: connection_with_cursor(cursor),
    )

    result = incident_service.correlate_alert_to_incident(
        alert_id
    )

    assert result.incident_id == incident_id
    assert result.created is False
    assert result.linked is True


def test_stronger_alert_escalates_incident(monkeypatch):
    alert_id = uuid4()
    incident_id = uuid4()

    cursor = MagicMock()
    cursor.fetchone.side_effect = [
        None,
        alert_row(
            alert_id=alert_id,
            severity="high",
        ),
        (incident_id, "medium"),
        (alert_id,),
    ]

    monkeypatch.setattr(
        incident_service.psycopg,
        "connect",
        lambda **kwargs: connection_with_cursor(cursor),
    )

    incident_service.correlate_alert_to_incident(
        alert_id
    )

    update_calls = [
        call
        for call in cursor.execute.call_args_list
        if "UPDATE incidents" in call.args[0]
    ]

    assert len(update_calls) == 1
    assert update_calls[0].args[1][0] == "high"

    history_details = [
        call.args[1][3]
        for call in cursor.execute.call_args_list
        if "INSERT INTO incident_history" in call.args[0]
    ]

    assert any(
        "medium to high" in details
        for details in history_details
    )


def test_missing_alert_is_rejected(monkeypatch):
    cursor = MagicMock()
    cursor.fetchone.side_effect = [
        None,
        None,
    ]

    monkeypatch.setattr(
        incident_service.psycopg,
        "connect",
        lambda **kwargs: connection_with_cursor(cursor),
    )

    with pytest.raises(
        ValueError,
        match="Alert does not exist",
    ):
        incident_service.correlate_alert_to_incident(
            uuid4()
        )


def test_nonpositive_window_is_rejected():
    with pytest.raises(
        ValueError,
        match="correlation window must be positive",
    ):
        incident_service.correlate_alert_to_incident(
            uuid4(),
            window=timedelta(0),
        )


def test_update_incident_status_appends_history(monkeypatch):
    cursor = MagicMock()
    cursor.rowcount = 1

    monkeypatch.setattr(
        incident_service.psycopg,
        "connect",
        lambda **kwargs: connection_with_cursor(cursor),
    )

    updated = incident_service.update_incident_status(
        uuid4(),
        "investigating",
    )

    assert updated is True

    sql_calls = [
        call.args[0]
        for call in cursor.execute.call_args_list
    ]

    assert any(
        "UPDATE incidents" in sql
        for sql in sql_calls
    )
    assert any(
        "INSERT INTO incident_history" in sql
        for sql in sql_calls
    )


def test_update_incident_status_rejects_unknown_state():
    with pytest.raises(
        ValueError,
        match="Unsupported incident status",
    ):
        incident_service.update_incident_status(
            uuid4(),
            "deleted",
        )
