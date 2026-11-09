from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from app.services import alert_service


def connection_with_cursor(cursor):
    connection = MagicMock()
    connection.cursor.return_value.__enter__.return_value = cursor

    context = MagicMock()
    context.__enter__.return_value = connection
    context.__exit__.return_value = False

    return context


def test_create_alert_for_detection_creates_alert(monkeypatch):
    detection_id = uuid4()
    alert_id = uuid4()

    cursor = MagicMock()
    cursor.fetchone.return_value = (alert_id,)

    monkeypatch.setattr(
        alert_service.psycopg,
        "connect",
        lambda **kwargs: connection_with_cursor(cursor),
    )

    result = alert_service.create_alert_for_detection(
        detection_id
    )

    assert result.alert_id == alert_id
    assert result.detection_id == detection_id
    assert result.created is True

    sql = cursor.execute.call_args_list[0].args[0]

    assert "INSERT INTO security_alerts" in sql
    assert "ON CONFLICT (detection_id)" in sql


def test_create_alert_reuses_existing_detection_alert(monkeypatch):
    detection_id = uuid4()
    existing_alert_id = uuid4()

    cursor = MagicMock()
    cursor.fetchone.side_effect = [
        None,
        (existing_alert_id,),
    ]

    monkeypatch.setattr(
        alert_service.psycopg,
        "connect",
        lambda **kwargs: connection_with_cursor(cursor),
    )

    result = alert_service.create_alert_for_detection(
        detection_id
    )

    assert result.alert_id == existing_alert_id
    assert result.created is False


def test_create_alert_rejects_missing_detection(monkeypatch):
    detection_id = uuid4()

    cursor = MagicMock()
    cursor.fetchone.side_effect = [
        None,
        None,
        None,
    ]

    monkeypatch.setattr(
        alert_service.psycopg,
        "connect",
        lambda **kwargs: connection_with_cursor(cursor),
    )

    with pytest.raises(
        ValueError,
        match="Detection does not exist",
    ):
        alert_service.create_alert_for_detection(
            detection_id
        )


def test_update_alert_status_acknowledged(monkeypatch):
    cursor = MagicMock()
    cursor.rowcount = 1

    monkeypatch.setattr(
        alert_service.psycopg,
        "connect",
        lambda **kwargs: connection_with_cursor(cursor),
    )

    updated = alert_service.update_alert_status(
        uuid4(),
        "acknowledged",
    )

    assert updated is True

    sql, params = cursor.execute.call_args.args

    assert "UPDATE security_alerts" in sql
    assert params[0] == "acknowledged"


def test_update_alert_status_records_resolution_note(monkeypatch):
    cursor = MagicMock()
    cursor.rowcount = 1

    monkeypatch.setattr(
        alert_service.psycopg,
        "connect",
        lambda **kwargs: connection_with_cursor(cursor),
    )

    updated = alert_service.update_alert_status(
        uuid4(),
        "resolved",
        resolution_note="Validated and contained.",
    )

    assert updated is True

    _, params = cursor.execute.call_args.args

    assert params[0] == "resolved"
    assert params[4] == "Validated and contained."


def test_update_alert_status_rejects_unknown_state():
    with pytest.raises(
        ValueError,
        match="Unsupported alert status",
    ):
        alert_service.update_alert_status(
            uuid4(),
            "deleted",
        )
