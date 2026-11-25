from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.api.routes import monitoring
from app.api import rbac
from app.api.routes.auth import SESSION_COOKIE
from app.services.auth_session_service import InvalidSession

TEST_TOKEN = "a" * 43



DEVICE_ID = UUID("12345678-1234-4234-8234-123456789abc")

HEADERS = {"Cookie": f"{SESSION_COOKIE}={TEST_TOKEN}"}

ENDPOINTS = [
    ("/dashboard/summary", "get_dashboard_summary"),
    ("/devices", "list_devices"),
    (f"/devices/{DEVICE_ID}", "get_device_detail"),
]


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv(
        "INTELSOC_ADMIN_API_KEY",
        "dashboard-test-key",
    )

    def validate(token):
        if token != TEST_TOKEN:
            raise InvalidSession()

        return {
            "role": "administrator",
            "status": "active",
        }

    monkeypatch.setattr(rbac, "validate_session", validate)

    with TestClient(
        app,
        base_url="https://intelsoc.test",
    ) as test_client:
        yield test_client


@pytest.mark.parametrize("endpoint,service", ENDPOINTS)
def test_missing_session(client, endpoint, service):
    response = client.get("/api/v1" + endpoint)
    assert response.status_code == 401


@pytest.mark.parametrize("endpoint,service", ENDPOINTS)
def test_legacy_admin_key_rejected(client, endpoint, service):
    response = client.get(
        "/api/v1" + endpoint,
        headers={"X-IntelSOC-Admin-Key": "dashboard-test-key"}
    )
    assert response.status_code == 401


@pytest.mark.parametrize("endpoint,service", ENDPOINTS)
def test_authorized_retrieval(
    client, monkeypatch, endpoint, service
):
    payload = (
        [{"device_id": str(DEVICE_ID)}]
        if service == "list_devices"
        else {"test_record": True}
    )

    monkeypatch.setattr(
        monitoring,
        service,
        lambda **kwargs: payload
    )

    response = client.get(
        "/api/v1" + endpoint,
        headers=HEADERS
    )

    assert response.status_code == 200
    assert response.json() == payload


@pytest.mark.parametrize("endpoint,service", ENDPOINTS)
def test_database_failure(
    client, monkeypatch, endpoint, service
):
    def retrieve(**kwargs):
        raise OSError("Internal storage error")

    monkeypatch.setattr(monitoring, service, retrieve)

    response = client.get(
        "/api/v1" + endpoint,
        headers=HEADERS
    )

    assert response.status_code == 503
    assert response.json() == {
        "detail": "Monitoring data unavailable"
    }


@pytest.mark.parametrize("field,value", [
    ("hostname", "TEST-PC"),
    ("platform", "windows"),
    ("status", "active"),
    ("criticality", "medium"),
])
def test_device_filters(
    client, monkeypatch, field, value
):
    def retrieve(**kwargs):
        assert kwargs[field] == value
        return [{field: value}]

    monkeypatch.setattr(
        monitoring, "list_devices", retrieve
    )

    response = client.get(
        "/api/v1/devices",
        headers=HEADERS,
        params={field: value}
    )

    assert response.status_code == 200
    assert response.json() == [{field: value}]


@pytest.mark.parametrize("params", [
    {"limit": 0},
    {"limit": 101},
    {"offset": -1},
    {"offset": 100001},
])
def test_invalid_pagination(client, params):
    response = client.get(
        "/api/v1/devices",
        headers=HEADERS,
        params=params
    )

    assert response.status_code == 422


def test_valid_pagination(client, monkeypatch):
    def retrieve(**kwargs):
        assert kwargs["limit"] == 5
        assert kwargs["offset"] == 10
        return []

    monkeypatch.setattr(
        monitoring, "list_devices", retrieve
    )

    response = client.get(
        "/api/v1/devices",
        headers=HEADERS,
        params={"limit": 5, "offset": 10}
    )

    assert response.status_code == 200
    assert response.json() == []


def test_device_detail(client, monkeypatch):
    def retrieve(**kwargs):
        assert kwargs["device_id"] == DEVICE_ID
        return {"device_id": DEVICE_ID}

    monkeypatch.setattr(
        monitoring, "get_device_detail", retrieve
    )

    response = client.get(
        f"/api/v1/devices/{DEVICE_ID}",
        headers=HEADERS
    )

    assert response.status_code == 200
    assert response.json()["device_id"] == str(DEVICE_ID)


def test_missing_device(client, monkeypatch):
    monkeypatch.setattr(
        monitoring,
        "get_device_detail",
        lambda **kwargs: None
    )

    response = client.get(
        f"/api/v1/devices/{DEVICE_ID}",
        headers=HEADERS
    )

    assert response.status_code == 404


def test_invalid_device_uuid(client):
    response = client.get(
        "/api/v1/devices/invalid-uuid",
        headers=HEADERS
    )

    assert response.status_code == 422
