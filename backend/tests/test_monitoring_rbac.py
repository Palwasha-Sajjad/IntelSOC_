import pytest

from fastapi.testclient import TestClient

from app.main import app
from app.api import rbac
from app.api.routes import monitoring
from app.api.routes.auth import SESSION_COOKIE
from app.services.auth_session_service import InvalidSession


RECORD_ID = "12345678-1234-4234-8234-123456789abc"
TOKEN = "b" * 43

ENDPOINTS = [
    ("/events", "list_events", "viewer"),
    ("/alerts", "list_alerts", "viewer"),
    ("/dashboard/summary", "get_dashboard_summary", "viewer"),
    ("/incidents", "list_incidents", "analyst"),
    (f"/alerts/{RECORD_ID}", "get_alert_detail", "analyst"),
    (f"/alerts/{RECORD_ID}/ti", "get_alert_ti", "analyst"),
    (f"/alerts/{RECORD_ID}/risk", "get_alert_risk", "analyst"),
    (f"/incidents/{RECORD_ID}", "get_incident_detail", "analyst"),
    ("/devices", "list_devices", "administrator"),
    (f"/devices/{RECORD_ID}", "get_device_detail", "administrator"),
]

ROLE_LEVELS = {
    "viewer": 1,
    "analyst": 2,
    "administrator": 3,
}


@pytest.mark.parametrize("endpoint,service,minimum_role", ENDPOINTS)
@pytest.mark.parametrize("role", [
    "viewer",
    "analyst",
    "administrator",
])
def test_monitoring_role_permissions(
    monkeypatch, endpoint, service, minimum_role, role
):
    calls = []

    def retrieve(**kwargs):
        calls.append(kwargs)
        return []

    def validate(token):
        if token != TOKEN:
            raise InvalidSession()

        return {
            "role": role,
            "status": "active",
        }

    monkeypatch.setattr(rbac, "validate_session", validate)
    monkeypatch.setattr(monitoring, service, retrieve)

    allowed = ROLE_LEVELS[role] >= ROLE_LEVELS[minimum_role]

    with TestClient(
        app,
        base_url="https://intelsoc.test",
    ) as client:

        response = client.get(
            "/api/v1" + endpoint,
            headers={
                "Cookie": f"{SESSION_COOKIE}={TOKEN}"
            },
        )

    assert response.status_code == (200 if allowed else 403)
    assert len(calls) == (1 if allowed else 0)


@pytest.mark.parametrize("role", [
    "viewer",
    "analyst",
    "administrator",
])
def test_alert_field_visibility(monkeypatch, role):

    basic_fields = {
        "alert_id": RECORD_ID,
        "title": "Test alert",
        "severity": "high",
        "status": "open",
        "overall_score": 65,
        "classification": "suspicious",
    }

    restricted_fields = {
        "rule_score": 45,
        "ti_score": 15,
        "lanobert_score": 5,
        "source_ip": "192.0.2.1",
        "target_user": "test_user",
        "detection_id": RECORD_ID,
        "score_version": "1.2",
        "future_sensitive_field": "restricted",
    }

    payload = {
        **basic_fields,
        **restricted_fields,
    }

    def validate(token):
        if token != TOKEN:
            raise InvalidSession()

        return {
            "role": role,
            "status": "active",
        }

    monkeypatch.setattr(rbac, "validate_session", validate)

    monkeypatch.setattr(
        monitoring,
        "list_alerts",
        lambda **kwargs: [payload],
    )

    with TestClient(
        app,
        base_url="https://intelsoc.test",
    ) as client:

        response = client.get(
            "/api/v1/alerts",
            headers={
                "Cookie": f"{SESSION_COOKIE}={TOKEN}"
            },
        )

    assert response.status_code == 200

    if role == "viewer":
        assert response.json() == [basic_fields]
    else:
        assert response.json() == [payload]
