"""Batch 5: API authorization and read-only contract tests (no database required)."""
from datetime import datetime, timezone
from uuid import uuid4

from fastapi.testclient import TestClient

from app.api.routes import ai_analysis
from app.main import app
from app.api import rbac
from app.api.routes.auth import SESSION_COOKIE
from app.services.auth_session_service import InvalidSession

import pytest

TOKEN = "c" * 43

HEADERS = {
    "Cookie": f"{SESSION_COOKIE}={TOKEN}"
}


@pytest.fixture(autouse=True)
def mock_session(monkeypatch):
    def validate(token):
        if token != TOKEN:
            raise InvalidSession()

        return {
            "role": "administrator",
            "status": "active",
        }

    monkeypatch.setattr(rbac, "validate_session", validate)


client = TestClient(app, base_url="https://intelsoc.test")
ENDPOINT = "/api/v1/ai/analysis"


def _row():
    return {
        "event_id": uuid4(), "model_version": "LAnoBERT-v0.2",
        "status": "processed", "anomaly_score": 7.08,
        "latency_ms": 333.8, "processed_at": datetime.now(timezone.utc),
        "hostname": "LAB-WIN-01", "source": "windows_eventlog",
        "event_type": "windows_security_event",
    }


def test_missing_session_rejected_before_db(monkeypatch):
    monkeypatch.setenv("INTELSOC_ADMIN_API_KEY", "admin-test-secret")
    monkeypatch.setattr(ai_analysis, "list_ai_analysis", lambda **kw: (_ for _ in ()).throw(AssertionError("DB called")))
    response = client.get(ENDPOINT)
    assert response.status_code == 401


def test_ingest_key_does_not_grant_access(monkeypatch):
    monkeypatch.setenv("INTELSOC_ADMIN_API_KEY", "admin-test-secret")
    monkeypatch.setenv("INTELSOC_INGEST_API_KEY", "ingest-key")
    response = client.get(ENDPOINT, headers={"X-IntelSOC-Key": "ingest-key"})
    assert response.status_code == 401


def test_admin_reads_only_bounded_metadata(monkeypatch):
    monkeypatch.setenv("INTELSOC_ADMIN_API_KEY", "admin-test-secret")
    seen = []
    monkeypatch.setattr(ai_analysis, "list_ai_analysis", lambda **kw: seen.append(kw) or [_row()])
    response = client.get(ENDPOINT + "?limit=1", headers=HEADERS)
    assert response.status_code == 200
    assert seen == [{"limit": 1}]
    data = response.json()[0]
    assert data["model_version"] == "LAnoBERT-v0.2"
    assert data["anomaly_score"] == 7.08
    assert "message" not in data
    assert "last_error" not in data
    assert "risk_score" not in data


def test_limits_rejected_before_db(monkeypatch):
    monkeypatch.setenv("INTELSOC_ADMIN_API_KEY", "admin-test-secret")
    monkeypatch.setattr(ai_analysis, "list_ai_analysis", lambda **kw: (_ for _ in ()).throw(AssertionError("DB called")))
    for limit in (0, 51, -1, "text"):
        resp = client.get(ENDPOINT, params={"limit": limit}, headers=HEADERS)
        assert resp.status_code == 422


def test_legacy_admin_key_rejected(monkeypatch):
    monkeypatch.setenv("INTELSOC_ADMIN_API_KEY", "admin-test-secret")
    response = client.get(
        ENDPOINT,
        headers={"X-IntelSOC-Admin-Key": "admin-test-secret"},
    )
    assert response.status_code == 401


def test_db_error_sanitized(monkeypatch):
    import psycopg
    monkeypatch.setenv("INTELSOC_ADMIN_API_KEY", "admin-test-secret")
    def fail(**kwargs):
        raise psycopg.OperationalError("secret_password=do_not_expose")
    monkeypatch.setattr(ai_analysis, "list_ai_analysis", fail)
    response = client.get(ENDPOINT, headers=HEADERS)
    assert response.status_code == 503
    assert "do_not_expose" not in response.text


@pytest.mark.parametrize("role,expected", [
    ("viewer", 403),
    ("analyst", 200),
    ("administrator", 200),
])
def test_ai_role_permissions(monkeypatch, role, expected):
    calls = []

    def validate(token):
        if token != TOKEN:
            raise InvalidSession()

        return {
            "role": role,
            "status": "active",
        }

    def retrieve(**kwargs):
        calls.append(kwargs)
        return [_row()]

    monkeypatch.setattr(rbac, "validate_session", validate)
    monkeypatch.setattr(ai_analysis, "list_ai_analysis", retrieve)

    response = client.get(ENDPOINT, headers=HEADERS)

    assert response.status_code == expected
    assert len(calls) == (0 if expected == 403 else 1)
