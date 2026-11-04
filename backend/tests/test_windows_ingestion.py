import json

import pytest
from fastapi.testclient import TestClient

from app.api.routes import events
from app.main import app


client = TestClient(
    app,
    headers={"X-IntelSOC-Key": "intelsoc-test-only-key"},
)


class FakeRedis:
    def __init__(self):
        self.entries = []

    def xadd(self, stream, fields):
        self.entries.append((stream, fields))
        return f"{len(self.entries)}-0".encode()

    def close(self):
        pass


@pytest.fixture
def fake_queue(monkeypatch):
    redis_client = FakeRedis()

    monkeypatch.setattr(
        events.redis,
        "Redis",
        lambda **kwargs: redis_client,
    )

    return redis_client


def sample_record():
    return {
        "ProviderName": "IntelSOC-Test",
        "EventID": 777,
        "TimeCreated": "2026-11-03 17:37:46 +0500",
        "EventRecordID": 28636,
        "Channel": "Application",
        "Computer": "LAB-PC",
        "Message": "First automatic Windows event",
    }


def test_windows_event_is_queued(fake_queue):
    response = client.post(
        "/api/v1/events/windows",
        json=[sample_record()],
    )

    assert response.status_code == 202
    assert response.json()["accepted"] == 1
    assert len(fake_queue.entries) == 1

    stream, fields = fake_queue.entries[0]
    payload = json.loads(fields["payload"])

    assert stream == "intelsoc:events"
    assert payload["source"] == "windows_eventlog"
    assert payload["hostname"] == "LAB-PC"


def test_invalid_batch_is_rejected(fake_queue):
    valid = sample_record()
    invalid = sample_record()
    del invalid["TimeCreated"]

    response = client.post(
        "/api/v1/events/windows",
        json=[valid, invalid],
    )

    assert response.status_code == 422
    assert len(fake_queue.entries) == 0


def test_repeated_event_has_same_id(fake_queue):
    record = sample_record()

    first = client.post(
        "/api/v1/events/windows",
        json=[record],
    )

    second = client.post(
        "/api/v1/events/windows",
        json=[record],
    )

    assert first.status_code == 202
    assert second.status_code == 202

    first_payload = json.loads(
        fake_queue.entries[0][1]["payload"]
    )
    second_payload = json.loads(
        fake_queue.entries[1][1]["payload"]
    )

    assert first_payload["event_id"] == second_payload["event_id"]
