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


def test_win002_incident_is_isolated_even_with_shared_user(monkeypatch):
    alert_id = uuid4()
    cursor = MagicMock()
    existing = alert_row(alert_id=alert_id)
    win002_row = (
        alert_id, "RULE-WIN-002", "Windows Security Audit Log Cleared",
        "high", existing[4], existing[5], None, NOW,
    )
    cursor.fetchone.side_effect = [None, win002_row, None, (alert_id,)]
    monkeypatch.setattr(
        incident_service.psycopg, "connect",
        lambda **kwargs: connection_with_cursor(cursor),
    )
    incident_service.correlate_alert_to_incident(alert_id)
    lookup = [
        call for call in cursor.execute.call_args_list
        if "FROM incidents" in call.args[0]
    ]
    assert len(lookup) == 1
    import hashlib
    expected = hashlib.sha256(
        f"isolated|RULE-WIN-002|{alert_id}".encode("utf-8")
    ).hexdigest()
    assert lookup[0].args[1][0] == expected


def test_no_user_no_source_alert_is_not_grouped_by_device_only(monkeypatch):
    alert_id = uuid4()
    cursor = MagicMock()
    existing = alert_row(alert_id=alert_id)
    unknown_row = (
        alert_id, "RULE-LIN-006", "Suspicious Execution",
        "medium", existing[4], None, None, NOW,
    )
    cursor.fetchone.side_effect = [None, unknown_row, None, (alert_id,)]
    monkeypatch.setattr(
        incident_service.psycopg, "connect",
        lambda **kwargs: connection_with_cursor(cursor),
    )
    incident_service.correlate_alert_to_incident(alert_id)
    lookup = [
        call for call in cursor.execute.call_args_list
        if "FROM incidents" in call.args[0]
    ]
    assert lookup[0].args[1][0] != incident_service.build_incident_correlation_key(
        device_id=existing[4], target_user=None, source_ip=None,
    )


def test_win003_incident_uses_own_isolated_correlation_key(monkeypatch):
    import hashlib
    alert_id = uuid4()
    cursor = MagicMock()
    baseline = alert_row(alert_id=alert_id)
    win003_row = (
        alert_id, "RULE-WIN-003", "Member Added to Local Administrators",
        "high", baseline[4], "S-1-5-21-1-2-3-1001", None, NOW,
    )
    cursor.fetchone.side_effect = [None, win003_row, None, (alert_id,)]
    monkeypatch.setattr(
        incident_service.psycopg, "connect",
        lambda **kwargs: connection_with_cursor(cursor),
    )
    incident_service.correlate_alert_to_incident(alert_id)
    lookup = [
        call for call in cursor.execute.call_args_list
        if "FROM incidents" in call.args[0]
    ]
    assert len(lookup) == 1
    expected = hashlib.sha256(
        f"isolated|RULE-WIN-003|{alert_id}".encode("utf-8")
    ).hexdigest()
    assert lookup[0].args[1][0] == expected


def test_win004_incident_does_not_merge_with_unrelated_login_alert(monkeypatch):
    import hashlib
    alert_id = uuid4()
    cursor = MagicMock()
    baseline = alert_row(alert_id=alert_id)
    row = (
        alert_id, "RULE-WIN-004", "Windows User Account Enabled",
        "medium", baseline[4], "LAB\\newuser", None, NOW,
    )
    cursor.fetchone.side_effect = [None, row, None, (alert_id,)]
    monkeypatch.setattr(
        incident_service.psycopg, "connect",
        lambda **kwargs: connection_with_cursor(cursor),
    )
    incident_service.correlate_alert_to_incident(alert_id)
    matches = [
        call for call in cursor.execute.call_args_list
        if "FROM incidents" in call.args[0]
    ]
    assert len(matches) == 1
    expected = hashlib.sha256(
        f"isolated|RULE-WIN-004|{alert_id}".encode("utf-8")
    ).hexdigest()
    assert matches[0].args[1][0] == expected


def test_win005_incident_isolated_from_unrelated_lifecycle_and_login(monkeypatch):
    import hashlib
    alert_id = uuid4()
    cursor = MagicMock()
    baseline = alert_row(alert_id=alert_id)
    row = (
        alert_id, "RULE-WIN-005", "Windows User Account Deleted",
        "medium", baseline[4], "LAB\\testuser", None, NOW,
    )
    cursor.fetchone.side_effect = [None, row, None, (alert_id,)]
    monkeypatch.setattr(
        incident_service.psycopg, "connect",
        lambda **kwargs: connection_with_cursor(cursor),
    )
    incident_service.correlate_alert_to_incident(alert_id)
    matches = [
        call for call in cursor.execute.call_args_list
        if "FROM incidents" in call.args[0]
    ]
    assert len(matches) == 1
    expected = hashlib.sha256(
        f"isolated|RULE-WIN-005|{alert_id}".encode("utf-8")
    ).hexdigest()
    assert matches[0].args[1][0] == expected


def test_win006_lockout_incident_uses_isolated_correlation_key(monkeypatch):
    import hashlib
    alert_id = uuid4()
    cursor = MagicMock()
    baseline = alert_row(alert_id=alert_id)
    row = (
        alert_id, "RULE-WIN-006", "Windows User Account Locked Out",
        "medium", baseline[4], "LAB\\lockeduser", None, NOW,
    )
    cursor.fetchone.side_effect = [None, row, None, (alert_id,)]
    monkeypatch.setattr(
        incident_service.psycopg, "connect",
        lambda **kwargs: connection_with_cursor(cursor),
    )
    incident_service.correlate_alert_to_incident(alert_id)
    matches = [
        call for call in cursor.execute.call_args_list
        if "FROM incidents" in call.args[0]
    ]
    assert len(matches) == 1
    expected = hashlib.sha256(
        f"isolated|RULE-WIN-006|{alert_id}".encode("utf-8")
    ).hexdigest()
    assert matches[0].args[1][0] == expected
