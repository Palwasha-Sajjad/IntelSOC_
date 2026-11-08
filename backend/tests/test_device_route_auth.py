from uuid import uuid4

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(
    app,
    headers={
        "X-IntelSOC-Key": "intelsoc-test-only-key",
    },
)


def sample_windows_record():
    return {
        "ProviderName": "Microsoft-Windows-Security-Auditing",
        "EventID": 4624,
        "TimeCreated": "2026-11-06 18:00:00 +0500",
        "EventRecordID": 400001,
        "Channel": "Security",
        "Computer": "LAB-WIN-01",
        "Message": "Successful logon test",
    }


def sample_linux_record():
    return {
        "_HOSTNAME": "LAB-LINUX-01",
        "_BOOT_ID": "11111111111111111111111111111111",
        "_SOURCE_REALTIME_TIMESTAMP": "1793970000000000",
        "_SYSTEMD_UNIT": "ssh.service",
        "_PID": "2222",
        "MESSAGE": (
            "Accepted password for test "
            "from 192.0.2.50 port 55122 ssh2"
        ),
    }


def make_fake_redis():
    class FakeRedis:
        def __init__(self):
            self.entries = []

        def xadd(self, stream, fields):
            self.entries.append((stream, fields))
            return b"1-0"

        def close(self):
            pass

    return FakeRedis()


def test_windows_ingestion_rejects_missing_device_id():
    response = client.post(
        "/api/v1/events/windows",
        json=[sample_windows_record()],
    )

    assert response.status_code == 401


def test_windows_ingestion_rejects_unknown_device(monkeypatch):
    from app.api import security

    monkeypatch.setattr(
        security,
        "get_device_by_id",
        lambda value: None,
    )

    response = client.post(
        "/api/v1/events/windows",
        headers={
            "X-Device-ID": str(uuid4()),
        },
        json=[sample_windows_record()],
    )

    assert response.status_code == 401


def test_windows_ingestion_accepts_active_device(monkeypatch):
    from app.api import security
    from app.api.routes import events

    device_id = uuid4()

    device = {
        "device_id": device_id,
        "hostname": "LAB-WIN-01",
        "platform": "windows",
        "status": "active",
    }

    monkeypatch.setattr(
        security,
        "get_device_by_id",
        lambda value: device,
    )

    fake_redis = make_fake_redis()

    monkeypatch.setattr(
        events.redis,
        "Redis",
        lambda **kwargs: fake_redis,
    )

    response = client.post(
        "/api/v1/events/windows",
        headers={
            "X-Device-ID": str(device_id),
        },
        json=[sample_windows_record()],
    )

    assert response.status_code == 202
    assert response.json()["accepted"] == 1
    assert len(fake_redis.entries) == 1


def test_linux_ingestion_rejects_missing_device_id():
    response = client.post(
        "/api/v1/events/linux",
        json=[sample_linux_record()],
    )

    assert response.status_code == 401


def test_linux_ingestion_rejects_unknown_device(monkeypatch):
    from app.api import security

    monkeypatch.setattr(
        security,
        "get_device_by_id",
        lambda value: None,
    )

    response = client.post(
        "/api/v1/events/linux",
        headers={
            "X-Device-ID": str(uuid4()),
        },
        json=[sample_linux_record()],
    )

    assert response.status_code == 401


def test_linux_ingestion_accepts_active_device(monkeypatch):
    from app.api import security
    from app.api.routes import events

    device_id = uuid4()

    device = {
        "device_id": device_id,
        "hostname": "LAB-LINUX-01",
        "platform": "linux",
        "status": "active",
    }

    monkeypatch.setattr(
        security,
        "get_device_by_id",
        lambda value: device,
    )

    fake_redis = make_fake_redis()

    monkeypatch.setattr(
        events.redis,
        "Redis",
        lambda **kwargs: fake_redis,
    )

    response = client.post(
        "/api/v1/events/linux",
        headers={
            "X-Device-ID": str(device_id),
        },
        json=[sample_linux_record()],
    )

    assert response.status_code == 202
    assert response.json()["accepted"] == 1
    assert len(fake_redis.entries) == 1
