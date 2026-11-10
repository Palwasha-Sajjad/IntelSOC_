import json
from uuid import uuid4

import pytest
import redis
from fastapi.testclient import TestClient

from app.api.routes import events
from app.api import security
from app.main import app


TEST_DEVICE_ID = uuid4()

client = TestClient(
    app,
    headers={
        "X-IntelSOC-Key": "intelsoc-test-only-key",
        "X-Device-ID": str(TEST_DEVICE_ID),
    },
)


class FakeRedis:
    def __init__(self):
        self.entries = []

    class Pipeline:
        def __init__(self, client):
            self.client = client
            self.pending = []

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def xadd(self, stream, fields):
            self.pending.append((stream, fields))
            return self

        def execute(self):
            start = len(self.client.entries)
            self.client.entries.extend(self.pending)
            return [
                f"{start + index + 1}-0".encode()
                for index in range(len(self.pending))
            ]

    def pipeline(self, transaction=True):
        assert transaction is True
        return self.Pipeline(self)

    def close(self):
        pass




@pytest.fixture(autouse=True)
def registered_test_device(monkeypatch):
    device = {
        "device_id": TEST_DEVICE_ID,
        "hostname": "LAB-PC",
        "platform": "windows",
        "status": "active",
    }

    monkeypatch.setattr(
        security,
        "get_device_by_id",
        lambda value: device,
    )

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
    assert payload["device_id"] == str(TEST_DEVICE_ID)

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

def test_large_windows_batch_has_compact_response(fake_queue):
    records = []

    for i in range(100):
        record = sample_record()
        record["EventRecordID"] = 30000 + i
        records.append(record)

    response = client.post(
        "/api/v1/events/windows",
        json=records,
    )

    assert response.status_code == 202
    assert response.json() == {
        "status": "queued",
        "accepted": 100,
    }

    assert len(response.content) < 512
    assert len(fake_queue.entries) == 100

def test_large_windows_security_event_is_queued(fake_queue):
    record = sample_record()

    record["Channel"] = "Security"
    record["EventID"] = 4624
    record["EventRecordID"] = 462401
    record["ProviderName"] = "Microsoft-Windows-Security-Auditing"
    record["Message"] = "Detailed Windows authentication event. " * 250

    response = client.post(
        "/api/v1/events/windows",
        json=[record],
    )

    assert response.status_code == 202
    assert response.json()["accepted"] == 1
    assert len(fake_queue.entries) == 1

    payload = json.loads(fake_queue.entries[0][1]["payload"])

    assert payload["event_type"] == "windows_security_event"
    assert payload["message"].endswith(record["Message"].strip())
    assert len(payload["message"]) > 2048

@pytest.mark.parametrize(
    "event_id,channel,provider",
    [
        (4648, "Security", "Microsoft-Windows-Security-Auditing"),
        (4688, "Security", "Microsoft-Windows-Security-Auditing"),
        (4698, "Security", "Microsoft-Windows-Security-Auditing"),
        (4702, "Security", "Microsoft-Windows-Security-Auditing"),
        (4720, "Security", "Microsoft-Windows-Security-Auditing"),
        (4722, "Security", "Microsoft-Windows-Security-Auditing"),
        (4732, "Security", "Microsoft-Windows-Security-Auditing"),
        (1102, "Security", "Microsoft-Windows-Eventlog"),
        (
            4104,
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-PowerShell",
        ),
    ],
)
def test_approved_windows_telemetry_is_accepted(
    fake_queue,
    event_id,
    channel,
    provider,
):
    record = sample_record()

    record["EventID"] = event_id
    record["EventRecordID"] = 50000 + event_id
    record["Channel"] = channel
    record["ProviderName"] = provider
    record["Message"] = (
        f"IntelSOC approved telemetry compatibility test "
        f"for EventID {event_id}"
    )

    response = client.post(
        "/api/v1/events/windows",
        json=[record],
    )

    assert response.status_code == 202
    assert response.json()["accepted"] == 1

    payload = json.loads(
        fake_queue.entries[-1][1]["payload"]
    )

    assert payload["source"] == "windows_eventlog"
    assert payload["device_id"] == str(TEST_DEVICE_ID)

    assert payload["raw_event"]["EventID"] == event_id
    assert payload["raw_event"]["Channel"] == channel
    assert payload["raw_event"]["ProviderName"] == provider

    assert f"EventID={event_id}" in payload["message"]


def test_windows_batch_queue_failure_is_all_or_nothing(monkeypatch):
    class FailingRedis(FakeRedis):
        class Pipeline(FakeRedis.Pipeline):
            def execute(self):
                raise redis.exceptions.ConnectionError("Redis unavailable")

    failing = FailingRedis()

    monkeypatch.setattr(
        events.redis,
        "Redis",
        lambda **kwargs: failing,
    )

    records = [sample_record(), sample_record()]
    records[1]["EventRecordID"] += 1

    response = client.post(
        "/api/v1/events/windows",
        json=records,
    )

    assert response.status_code == 503
    assert failing.entries == []
