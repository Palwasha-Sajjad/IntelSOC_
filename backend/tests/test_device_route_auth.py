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


def test_windows_ingestion_rejects_missing_registered_device_identity():
    response = client.post(
        "/api/v1/events/windows",
        json=[sample_windows_record()],
    )

    assert response.status_code == 401


def test_windows_ingestion_accepts_matching_registered_device(monkeypatch):
    from uuid import uuid4

    from app.api import security
    from app.api.routes import events

    device_id = uuid4()

    device = {
        "device_id": device_id,
        "hostname": "LAB-WIN-01",
        "platform": "windows",
        "certificate_common_name": "intelsoc-device-win01",
        "certificate_fingerprint": "AA" * 32,
        "status": "active",
    }

    monkeypatch.setattr(
        security,
        "get_device_by_id",
        lambda value: device,
    )

    class FakeRedis:
        def __init__(self):
            self.entries = []

        def xadd(self, stream, fields):
            self.entries.append((stream, fields))
            return b"1-0"

        def close(self):
            pass

    fake_redis = FakeRedis()

    monkeypatch.setattr(
        events.redis,
        "Redis",
        lambda **kwargs: fake_redis,
    )

    response = client.post(
        "/api/v1/events/windows",
        headers={
            "X-IntelSOC-Key": "intelsoc-test-only-key",
            "X-Device-ID": str(device_id),
            "X-IntelSOC-Client-CN": "intelsoc-device-win01",
            "X-IntelSOC-Client-Fingerprint": "AA" * 32,
        },
        json=[sample_windows_record()],
    )

    assert response.status_code == 202
    assert response.json()["accepted"] == 1
    assert len(fake_redis.entries) == 1


def sample_linux_record():
    return {
        "_HOSTNAME": "LAB-LINUX-01",
        "_BOOT_ID": "11111111111111111111111111111111",
        "_SOURCE_REALTIME_TIMESTAMP": "1793970000000000",
        "_SYSTEMD_UNIT": "ssh.service",
        "_PID": "2222",
        "MESSAGE": "Accepted password for test from 192.0.2.50 port 55122 ssh2",
    }


def test_linux_ingestion_rejects_missing_registered_device_identity():
    response = client.post(
        "/api/v1/events/linux",
        json=[sample_linux_record()],
    )

    assert response.status_code == 401


def test_linux_ingestion_accepts_matching_registered_device(monkeypatch):
    from uuid import uuid4

    from app.api import security
    from app.api.routes import events

    device_id = uuid4()

    device = {
        "device_id": device_id,
        "hostname": "LAB-LINUX-01",
        "platform": "linux",
        "certificate_common_name": "intelsoc-device-linux01",
        "certificate_fingerprint": "CC" * 32,
        "status": "active",
    }

    monkeypatch.setattr(
        security,
        "get_device_by_id",
        lambda value: device,
    )

    class FakeRedis:
        def __init__(self):
            self.entries = []

        def xadd(self, stream, fields):
            self.entries.append((stream, fields))
            return b"1-0"

        def close(self):
            pass

    fake_redis = FakeRedis()

    monkeypatch.setattr(
        events.redis,
        "Redis",
        lambda **kwargs: fake_redis,
    )

    response = client.post(
        "/api/v1/events/linux",
        headers={
            "X-IntelSOC-Key": "intelsoc-test-only-key",
            "X-Device-ID": str(device_id),
            "X-IntelSOC-Client-CN": "intelsoc-device-linux01",
            "X-IntelSOC-Client-Fingerprint": "CC" * 32,
        },
        json=[sample_linux_record()],
    )

    assert response.status_code == 202
    assert response.json()["accepted"] == 1
    assert len(fake_redis.entries) == 1
