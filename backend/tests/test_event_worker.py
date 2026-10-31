
from unittest.mock import MagicMock

import psycopg
import pytest
import redis

from app.workers import event_worker as worker
from app.schemas.event import SecurityEvent


def test_valid_event(monkeypatch):
    client = MagicMock()
    saved = []

    monkeypatch.setattr(
        worker,
        "save_event",
        lambda payload: saved.append(payload),
    )

    result = worker.process_message(
        client, "11-0", {"payload": "valid"}
    )

    assert result == "saved"
    assert saved == ["valid"]

    client.xack.assert_called_once_with(
        worker.STREAM, worker.GROUP, "11-0"
    )
    client.pipeline.assert_not_called()


def test_invalid_event_goes_to_dlq(monkeypatch):
    client = MagicMock()

    def validate(payload):
        SecurityEvent.model_validate_json(payload)

    monkeypatch.setattr(worker, "save_event", validate)

    result = worker.process_message(
        client,
        "12-0",
        {"payload": "this-is-not-json"},
    )

    pipe = client.pipeline.return_value.__enter__.return_value

    assert result == "dlq"

    pipe.xadd.assert_called_once()
    pipe.xack.assert_called_once_with(
        worker.STREAM, worker.GROUP, "12-0"
    )
    pipe.execute.assert_called_once()

    client.pipeline.assert_called_once_with(
        transaction=True
    )
    client.xack.assert_not_called()


def test_missing_payload_goes_to_dlq():
    client = MagicMock()

    result = worker.process_message(
        client, "13-0", {}
    )

    assert result == "dlq"

    pipe = client.pipeline.return_value.__enter__.return_value
    pipe.xadd.assert_called_once()
    pipe.xack.assert_called_once()
    pipe.execute.assert_called_once()


def test_database_failure_not_acknowledged(monkeypatch):
    client = MagicMock()

    def fail_database(payload):
        raise psycopg.OperationalError("Database unavailable")

    monkeypatch.setattr(
        worker, "save_event", fail_database
    )

    with pytest.raises(psycopg.OperationalError):
        worker.process_message(
            client, "14-0", {"payload": "valid"}
        )

    client.xack.assert_not_called()
    client.pipeline.assert_not_called()


def test_dlq_failure_not_silently_ignored(monkeypatch):
    client = MagicMock()

    def invalid_payload(payload):
        SecurityEvent.model_validate_json(payload)

    monkeypatch.setattr(
        worker, "save_event", invalid_payload
    )

    pipe = client.pipeline.return_value.__enter__.return_value
    pipe.execute.side_effect = (
        redis.exceptions.ConnectionError("Redis unavailable")
    )

    with pytest.raises(redis.exceptions.ConnectionError):
        worker.process_message(
            client,
            "15-0",
            {"payload": "this-is-not-json"},
        )

    client.xack.assert_not_called()
