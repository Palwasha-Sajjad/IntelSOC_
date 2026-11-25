import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.api.routes import monitoring
from app.api import rbac
from app.api.routes.auth import SESSION_COOKIE
from app.services.auth_session_service import InvalidSession

TEST_TOKEN = "a" * 43



@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv(
        "INTELSOC_ADMIN_API_KEY",
        "monitoring-test-key",
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


HEADERS = {"Cookie": f"{SESSION_COOKIE}={TEST_TOKEN}"}


@pytest.mark.parametrize("endpoint", [
    "events", "alerts", "incidents"
])
def test_missing_session(client, endpoint):
    response = client.get(f"/api/v1/{endpoint}")
    assert response.status_code == 401


@pytest.mark.parametrize("endpoint", [
    "events", "alerts", "incidents"
])
def test_legacy_admin_key_rejected(client, endpoint):
    response = client.get(
        f"/api/v1/{endpoint}",
        headers={"X-IntelSOC-Admin-Key": "monitoring-test-key"}
    )
    assert response.status_code == 401


@pytest.mark.parametrize("endpoint,service", [
    ("events", "list_events"),
    ("alerts", "list_alerts"),
    ("incidents", "list_incidents"),
])
def test_authorized_retrieval(
    client, monkeypatch, endpoint, service
):
    calls = []

    def retrieve(**kwargs):
        calls.append(kwargs)
        return [{"test_record": True}]

    monkeypatch.setattr(monitoring, service, retrieve)

    response = client.get(
        f"/api/v1/{endpoint}",
        headers=HEADERS,
        params={"limit": 5, "offset": 10}
    )

    assert response.status_code == 200
    assert response.json() == [{"test_record": True}]
    assert len(calls) == 1
    assert calls[0]["limit"] == 5
    assert calls[0]["offset"] == 10


@pytest.mark.parametrize("endpoint", [
    "events", "alerts", "incidents"
])
@pytest.mark.parametrize("params", [
    {"limit": 0},
    {"limit": 101},
    {"offset": -1},
    {"offset": 100001},
    {"device_id": "invalid-uuid"},
])
def test_invalid_parameters(client, endpoint, params):
    response = client.get(
        f"/api/v1/{endpoint}",
        headers=HEADERS,
        params=params
    )
    assert response.status_code == 422


def test_event_hostname_filter(client, monkeypatch):
    def retrieve(**kwargs):
        assert kwargs["hostname"] == "TEST-PC"
        return [{"hostname": "TEST-PC"}]

    monkeypatch.setattr(
        monitoring, "list_events", retrieve
    )

    response = client.get(
        "/api/v1/events",
        headers=HEADERS,
        params={"hostname": "TEST-PC"}
    )

    assert response.status_code == 200
    assert response.json() == [{"hostname": "TEST-PC"}]


@pytest.mark.parametrize("endpoint,service", [
    ("events", "list_events"),
    ("alerts", "list_alerts"),
    ("incidents", "list_incidents"),
])
def test_storage_failure(
    client, monkeypatch, endpoint, service
):
    def retrieve(**kwargs):
        raise OSError("Internal storage error")

    monkeypatch.setattr(monitoring, service, retrieve)

    response = client.get(
        f"/api/v1/{endpoint}",
        headers=HEADERS
    )

    assert response.status_code == 503
    assert response.json() == {
        "detail": "Monitoring data unavailable"
    }
