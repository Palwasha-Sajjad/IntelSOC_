import pytest
from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


EVENT = {
    "timestamp": "2026-10-31T10:00:00+00:00",
    "source": "windows",
    "hostname": "test-pc",
    "event_type": "failed_login",
    "message": "Failed login",
}

WINDOWS_EVENT = {
    "ProviderName": "IntelSOC-Test",
    "EventID": 777,
    "TimeCreated": "2026-11-03 17:37:46 +0500",
    "EventRecordID": 28636,
    "Channel": "Application",
    "Computer": "LAB-PC",
    "Message": "Test event",
}

LINUX_EVENT = {
    "_HOSTNAME": "LAB-LINUX-01",
    "_BOOT_ID": "11111111111111111111111111111111",
    "_SOURCE_REALTIME_TIMESTAMP": "1793970000000000",
    "_SYSTEMD_UNIT": "ssh.service",
    "_PID": "2222",
    "MESSAGE": "Accepted publickey for test from 192.0.2.50 port 55122 ssh2",
}

ENDPOINTS = [
    ("/api/v1/events", EVENT),
    ("/api/v1/events/windows", [WINDOWS_EVENT]),
    ("/api/v1/events/linux", [LINUX_EVENT]),
]


@pytest.mark.parametrize("path,payload", ENDPOINTS)
def test_missing_api_key(path, payload):
    response = client.post(path, json=payload)

    assert response.status_code == 401


@pytest.mark.parametrize("path,payload", ENDPOINTS)
def test_incorrect_api_key(path, payload):
    response = client.post(
        path,
        json=payload,
        headers={"X-IntelSOC-Key": "wrong-key"},
    )

    assert response.status_code == 401


def test_unconfigured_api_key(monkeypatch):
    monkeypatch.delenv(
        "INTELSOC_INGEST_API_KEY",
        raising=False,
    )

    response = client.post(
        "/api/v1/events",
        json=EVENT,
        headers={"X-IntelSOC-Key": "any-key"},
    )

    assert response.status_code == 503
