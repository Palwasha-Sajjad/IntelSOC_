import json
from unittest.mock import MagicMock

import redis
from fastapi.testclient import TestClient

from app.main import app
from app.api.routes import events


client = TestClient(
    app,
    headers={"X-IntelSOC-Key": "intelsoc-test-only-key"},
)


def sample_event():
    return {
        "timestamp": "2026-10-31T10:00:00+00:00",
        "source": "windows",
        "hostname": "test-pc",
        "event_type": "failed_login",
        "src_ip": "192.0.2.10",
        "message": "Failed login for admin"
    }


# TEST 1: Valid events should be queued
def test_valid_event(monkeypatch):
    fake_redis = MagicMock()
    pipe = fake_redis.pipeline.return_value.__enter__.return_value
    pipe.execute.return_value = [b"12345-0"]

    monkeypatch.setattr(
        events.redis,
        "Redis",
        lambda **kwargs: fake_redis
    )

    response = client.post(
        "/api/v1/events",
        json=sample_event()
    )

    assert response.status_code == 202
    assert response.json()["status"] == "queued"
    assert response.json()["stream_id"] == "12345-0"

    fake_redis.pipeline.assert_called_once_with(transaction=True)
    pipe.xadd.assert_called_once()

    args, kwargs = pipe.xadd.call_args

    assert args[0] == "intelsoc:events"

    stored_event = json.loads(args[1]["payload"])

    assert stored_event["event_type"] == "failed_login"
    assert stored_event["event_id"] == response.json()["event_id"]


# TEST 2: Invalid events must be rejected
def test_invalid_event():
    bad_event = sample_event()

    # A timestamp without a timezone is invalid.
    bad_event["timestamp"] = "2026-10-31T10:00:00"

    response = client.post(
        "/api/v1/events",
        json=bad_event
    )

    assert response.status_code == 422


# TEST 3: Redis failure must be handled
def test_redis_unavailable(monkeypatch):
    fake_redis = MagicMock()
    pipe = fake_redis.pipeline.return_value.__enter__.return_value
    pipe.execute.side_effect = (
        redis.exceptions.ConnectionError("Redis unavailable")
    )

    monkeypatch.setattr(
        events.redis,
        "Redis",
        lambda **kwargs: fake_redis
    )

    response = client.post(
        "/api/v1/events",
        json=sample_event()
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "Event queue unavailable"
