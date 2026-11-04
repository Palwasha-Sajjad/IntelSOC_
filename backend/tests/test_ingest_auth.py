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

ENDPOINTS = [
    ("/api/v1/events", EVENT),
    ("/api/v1/events/windows", [WINDOWS_EVENT]),
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
