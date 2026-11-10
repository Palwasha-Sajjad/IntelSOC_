from uuid import uuid4

from fastapi.testclient import TestClient

from app.api import security
from app.api.routes import events
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
                self.client.entries.extend(self.pending)
                return [
                    f"{index + 1}-0".encode()
                    for index in range(len(self.pending))
                ]

        def pipeline(self, transaction=True):
            assert transaction is True
            return self.Pipeline(self)

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


def test_successful_windows_ingestion_updates_last_seen(monkeypatch):
    from uuid import uuid4

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

    seen = []

    monkeypatch.setattr(
        events,
        "update_device_last_seen",
        lambda value: seen.append(value) or True,
    )

    response = client.post(
        "/api/v1/events/windows",
        headers={
            "X-Device-ID": str(device_id),
        },
        json=[sample_windows_record()],
    )

    assert response.status_code == 202
    assert seen == [device_id]

def sample_linux_audit_record():
    return {
        "log": (
            "type=USER_MGMT "
            "msg=audit(1793971000.123:501): "
            "pid=1234 uid=0 auid=1000 "
            'acct="newuser" res=success'
        )
    }


def test_linux_audit_event_is_accepted(
    monkeypatch,
):
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

    queued = []

    def fake_queue_events(batch):
        queued.extend(batch)
        return [b"1-0" for _ in batch]

    monkeypatch.setattr(
        events,
        "_queue_events",
        fake_queue_events,
    )

    monkeypatch.setattr(
        events,
        "update_device_last_seen",
        lambda value: None,
    )

    response = client.post(
        "/api/v1/events/linux",
        headers={
            "X-Device-ID": str(device_id),
        },
        json=[sample_linux_audit_record()],
    )

    assert response.status_code == 202
    assert response.json()["accepted"] == 1

    assert len(queued) == 1

    event = queued[0]

    assert event.source == "linux_audit"
    assert event.event_type == (
        "linux_account_audit_event"
    )
    assert event.hostname == "LAB-LINUX-01"
    assert event.device_id == device_id

    assert (
        event.raw_event
        == sample_linux_audit_record()
    )


def test_linux_unsupported_audit_type_is_rejected(
    monkeypatch,
):
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

    record = {
        "log": (
            "type=SOCKADDR "
            "msg=audit(1793971000.123:502): "
            "saddr=02000050C0000201"
        )
    }

    response = client.post(
        "/api/v1/events/linux",
        headers={
            "X-Device-ID": str(device_id),
        },
        json=[record],
    )

    assert response.status_code == 422



def test_windows_ingestion_rejects_linux_registered_device(monkeypatch):
    device_id = uuid4()
    monkeypatch.setattr(
        security,
        "get_device_by_id",
        lambda value: {
            "device_id": device_id,
            "hostname": "LAB-LINUX-01",
            "platform": "linux",
            "status": "active",
        },
    )

    response = client.post(
        "/api/v1/events/windows",
        headers={"X-Device-ID": str(device_id)},
        json=[sample_windows_record()],
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Device is not registered as windows"


def test_linux_ingestion_rejects_windows_registered_device(monkeypatch):
    device_id = uuid4()
    monkeypatch.setattr(
        security,
        "get_device_by_id",
        lambda value: {
            "device_id": device_id,
            "hostname": "LAB-WIN-01",
            "platform": "windows",
            "status": "active",
        },
    )

    response = client.post(
        "/api/v1/events/linux",
        headers={"X-Device-ID": str(device_id)},
        json=[sample_linux_record()],
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Device is not registered as linux"
