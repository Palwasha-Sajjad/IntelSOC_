from datetime import datetime, timezone
from uuid import uuid4

from fastapi.testclient import TestClient

from app.api.routes import device_management
from app.main import app


import pytest

from app.api import rbac
from app.api.routes.auth import SESSION_COOKIE
from app.services.auth_session_service import InvalidSession


ORIGIN = "https://intelsoc.test"
TOKEN = "d" * 43

HEADERS = {
    "Origin": ORIGIN,
    "Cookie": f"{SESSION_COOKIE}={TOKEN}",
}

client = TestClient(app, base_url=ORIGIN)


@pytest.fixture(autouse=True)
def mock_session(monkeypatch):
    monkeypatch.setenv(
        "INTELSOC_DASHBOARD_ORIGIN",
        ORIGIN,
    )

    def validate(token):
        if token != TOKEN:
            raise InvalidSession()

        return {
            "role": "administrator",
            "status": "active",
        }

    monkeypatch.setattr(rbac, "validate_session", validate)


def _device(device_id, criticality="high"):
    return {
        "device_id": device_id,
        "hostname": "LAB-WIN-CRITICAL",
        "platform": "windows",
        "status": "active",
        "criticality": criticality,
        "created_at": datetime.now(timezone.utc),
        "last_seen_at": None,
    }


def test_criticality_update_requires_session(monkeypatch):
    monkeypatch.setenv(
        "INTELSOC_ADMIN_API_KEY",
        "admin-test-key",
    )

    response = client.patch(
        f"/api/v1/devices/{uuid4()}/criticality",
        headers={"Origin": ORIGIN},
        json={"criticality": "high"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == (
        "Invalid or expired session"
    )


def test_criticality_update_rejects_ingestion_key(monkeypatch):
    monkeypatch.setenv(
        "INTELSOC_ADMIN_API_KEY",
        "admin-test-key",
    )
    monkeypatch.setenv(
        "INTELSOC_INGEST_API_KEY",
        "ingest-test-key",
    )

    response = client.patch(
        f"/api/v1/devices/{uuid4()}/criticality",
        headers={
            "Origin": ORIGIN,
            "X-IntelSOC-Key": "ingest-test-key",
        },
        json={"criticality": "high"},
    )

    assert response.status_code == 401


def test_admin_can_update_device_criticality(monkeypatch):
    device_id = uuid4()
    captured = {}

    monkeypatch.setenv(
        "INTELSOC_ADMIN_API_KEY",
        "admin-test-key",
    )

    def fake_update(device_id, criticality):
        captured["device_id"] = device_id
        captured["criticality"] = criticality
        return _device(device_id, criticality)

    monkeypatch.setattr(
        device_management,
        "update_device_criticality",
        fake_update,
    )

    response = client.patch(
        f"/api/v1/devices/{device_id}/criticality",
        headers=HEADERS,
        json={"criticality": "high"},
    )

    assert response.status_code == 200
    assert response.json()["device_id"] == str(device_id)
    assert response.json()["criticality"] == "high"
    assert captured["device_id"] == device_id
    assert captured["criticality"] == "high"


def test_criticality_update_rejects_unsupported_value(monkeypatch):
    monkeypatch.setenv(
        "INTELSOC_ADMIN_API_KEY",
        "admin-test-key",
    )

    response = client.patch(
        f"/api/v1/devices/{uuid4()}/criticality",
        headers=HEADERS,
        json={"criticality": "critical"},
    )

    assert response.status_code == 422


def test_criticality_update_returns_404_for_unknown_device(monkeypatch):
    monkeypatch.setenv(
        "INTELSOC_ADMIN_API_KEY",
        "admin-test-key",
    )

    monkeypatch.setattr(
        device_management,
        "update_device_criticality",
        lambda device_id, criticality: None,
    )

    response = client.patch(
        f"/api/v1/devices/{uuid4()}/criticality",
        headers=HEADERS,
        json={"criticality": "low"},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Device not found"


@pytest.mark.parametrize("role,expected", [
    ("viewer", 403),
    ("analyst", 403),
    ("administrator", 200),
])
def test_criticality_role_permissions(monkeypatch, role, expected):
    calls = []

    def validate(token):
        if token != TOKEN:
            raise InvalidSession()

        return {
            "role": role,
            "status": "active",
        }

    def update(device_id, criticality):
        calls.append(device_id)
        return _device(device_id, criticality)

    monkeypatch.setattr(rbac, "validate_session", validate)
    monkeypatch.setattr(
        device_management,
        "update_device_criticality",
        update,
    )

    response = client.patch(
        f"/api/v1/devices/{uuid4()}/criticality",
        headers=HEADERS,
        json={"criticality": "high"},
    )

    assert response.status_code == expected
    assert len(calls) == (1 if expected == 200 else 0)


@pytest.mark.parametrize("origin", [
    None,
    "https://untrusted.example.com",
    "http://intelsoc.test",
    "null",
])
def test_criticality_csrf_protection(monkeypatch, origin):
    calls = []

    monkeypatch.setattr(
        device_management,
        "update_device_criticality",
        lambda **kwargs: calls.append(kwargs),
    )

    headers = {
        "Cookie": f"{SESSION_COOKIE}={TOKEN}",
    }

    if origin is not None:
        headers["Origin"] = origin

    response = client.patch(
        f"/api/v1/devices/{uuid4()}/criticality",
        headers=headers,
        json={"criticality": "high"},
    )

    assert response.status_code == 403
    assert calls == []


def test_criticality_rejects_legacy_admin_key(monkeypatch):
    monkeypatch.setenv(
        "INTELSOC_ADMIN_API_KEY",
        "admin-test-key",
    )

    calls = []

    monkeypatch.setattr(
        device_management,
        "update_device_criticality",
        lambda **kwargs: calls.append(kwargs),
    )

    response = client.patch(
        f"/api/v1/devices/{uuid4()}/criticality",
        headers={
            "Origin": ORIGIN,
            "X-IntelSOC-Admin-Key": "admin-test-key",
        },
        json={"criticality": "high"},
    )

    assert response.status_code == 401
    assert calls == []
