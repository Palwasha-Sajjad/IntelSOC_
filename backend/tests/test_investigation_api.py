from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.api.routes import monitoring


RECORD_ID = UUID("12345678-1234-4234-8234-123456789abc")

HEADERS = {
    "X-IntelSOC-Admin-Key": "investigation-test-key"
}

ENDPOINTS = [
    (f"/alerts/{RECORD_ID}", "get_alert_detail", "alert_id"),
    (f"/alerts/{RECORD_ID}/ti", "get_alert_ti", "alert_id"),
    (f"/alerts/{RECORD_ID}/risk", "get_alert_risk", "alert_id"),
    (f"/incidents/{RECORD_ID}", "get_incident_detail", "incident_id"),
]


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv(
        "INTELSOC_ADMIN_API_KEY",
        "investigation-test-key"
    )

    with TestClient(app) as test_client:
        yield test_client


@pytest.mark.parametrize("endpoint,service,id_field", ENDPOINTS)
def test_missing_key(client, endpoint, service, id_field):
    response = client.get("/api/v1" + endpoint)
    assert response.status_code == 401


@pytest.mark.parametrize("endpoint,service,id_field", ENDPOINTS)
def test_invalid_key(client, endpoint, service, id_field):
    response = client.get(
        "/api/v1" + endpoint,
        headers={"X-IntelSOC-Admin-Key": "invalid"}
    )
    assert response.status_code == 401


@pytest.mark.parametrize("endpoint,service,id_field", ENDPOINTS)
def test_authorized_retrieval(
    client, monkeypatch, endpoint, service, id_field
):
    def retrieve(**kwargs):
        assert kwargs[id_field] == RECORD_ID
        return {"record_id": str(RECORD_ID)}

    monkeypatch.setattr(monitoring, service, retrieve)

    response = client.get(
        "/api/v1" + endpoint,
        headers=HEADERS
    )

    assert response.status_code == 200
    assert response.json()["record_id"] == str(RECORD_ID)


@pytest.mark.parametrize("endpoint,service,id_field", ENDPOINTS)
def test_missing_record(
    client, monkeypatch, endpoint, service, id_field
):
    monkeypatch.setattr(
        monitoring, service, lambda **kwargs: None
    )

    response = client.get(
        "/api/v1" + endpoint,
        headers=HEADERS
    )

    assert response.status_code == 404


@pytest.mark.parametrize("endpoint,service,id_field", ENDPOINTS)
def test_invalid_uuid(client, endpoint, service, id_field):
    invalid = endpoint.replace(str(RECORD_ID), "invalid-uuid")

    response = client.get(
        "/api/v1" + invalid,
        headers=HEADERS
    )

    assert response.status_code == 422


@pytest.mark.parametrize("endpoint,service,id_field", ENDPOINTS)
def test_database_failure(
    client, monkeypatch, endpoint, service, id_field
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


def test_empty_ti_results(client, monkeypatch):
    monkeypatch.setattr(
        monitoring,
        "get_alert_ti",
        lambda **kwargs: []
    )

    response = client.get(
        f"/api/v1/alerts/{RECORD_ID}/ti",
        headers=HEADERS
    )

    assert response.status_code == 200
    assert response.json() == []


def test_pending_risk_assessment(client, monkeypatch):
    monkeypatch.setattr(
        monitoring,
        "get_alert_risk",
        lambda **kwargs: {
            "alert_id": RECORD_ID,
            "assessment": None,
        }
    )

    response = client.get(
        f"/api/v1/alerts/{RECORD_ID}/risk",
        headers=HEADERS
    )

    assert response.status_code == 200
    assert response.json()["assessment"] is None
