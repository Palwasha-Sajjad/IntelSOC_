from datetime import datetime, timezone
from uuid import uuid4

from fastapi.testclient import TestClient

from app.api.routes import device_management
from app.main import app


client = TestClient(app)


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


def test_criticality_update_requires_dedicated_admin_key(monkeypatch):
    monkeypatch.setenv(
        "INTELSOC_ADMIN_API_KEY",
        "admin-test-key",
    )

    response = client.patch(
        f"/api/v1/devices/{uuid4()}/criticality",
        json={"criticality": "high"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == (
        "Invalid or missing administrator API key"
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
            "X-IntelSOC-Admin-Key": "ingest-test-key",
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
        headers={
            "X-IntelSOC-Admin-Key": "admin-test-key",
        },
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
        headers={
            "X-IntelSOC-Admin-Key": "admin-test-key",
        },
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
        headers={
            "X-IntelSOC-Admin-Key": "admin-test-key",
        },
        json={"criticality": "low"},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Device not found"
