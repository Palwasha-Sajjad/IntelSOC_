"""Batch 6: RBAC-protected AI summary route (isolated, no PostgreSQL)."""
from datetime import datetime, timezone

import psycopg
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
URL = "/api/v1/ai/summary"


def sample_summary():
    return {"model_version": "LAnoBERT-v0.2", "total": 4,
            "processed": 3, "failed": 1, "skipped": 0,
            "average_latency_ms": 90.25,
            "last_processed_at": datetime(2026, 11, 21, tzinfo=timezone.utc)}


def test_summary_requires_session_before_database(monkeypatch):
    monkeypatch.setenv("INTELSOC_ADMIN_API_KEY", "summary-admin")
    monkeypatch.setattr(ai_analysis, "summarize_ai_analysis", lambda: (_ for _ in ()).throw(AssertionError("database called")))
    assert client.get(URL).status_code == 401


def test_summary_rejects_ingest_key(monkeypatch):
    monkeypatch.setenv("INTELSOC_ADMIN_API_KEY", "summary-admin")
    monkeypatch.setenv("INTELSOC_INGEST_API_KEY", "summary-ingest")
    assert client.get(URL, headers={"X-IntelSOC-Key": "summary-ingest"}).status_code == 401


def test_admin_sees_only_aggregate_statistics(monkeypatch):
    monkeypatch.setenv("INTELSOC_ADMIN_API_KEY", "summary-admin")
    monkeypatch.setattr(ai_analysis, "summarize_ai_analysis", sample_summary)
    response = client.get(URL, headers=HEADERS)
    assert response.status_code == 200
    result = response.json()
    assert result["total"] == 4 and result["processed"] == 3
    assert result["average_latency_ms"] == 90.25
    assert set(result) == {"model_version", "total", "processed", "failed", "skipped", "average_latency_ms", "last_processed_at"}
    assert not any(key in result for key in ("anomaly_score", "risk_score", "message", "device_id", "hostname"))


def test_storage_errors_sanitized(monkeypatch):
    monkeypatch.setenv("INTELSOC_ADMIN_API_KEY", "summary-admin")
    def fail():
        raise psycopg.OperationalError("password=secret-value")
    monkeypatch.setattr(ai_analysis, "summarize_ai_analysis", fail)
    response = client.get(URL, headers=HEADERS)
    assert response.status_code == 503
    assert "secret-value" not in response.text


def test_summary_rejects_legacy_admin_key(monkeypatch):
    monkeypatch.setenv("INTELSOC_ADMIN_API_KEY", "summary-admin")
    response = client.get(
        URL,
        headers={"X-IntelSOC-Admin-Key": "summary-admin"},
    )
    assert response.status_code == 401


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
        return sample_summary()

    monkeypatch.setattr(rbac, "validate_session", validate)
    monkeypatch.setattr(ai_analysis, "summarize_ai_analysis", retrieve)

    response = client.get(URL, headers=HEADERS)

    assert response.status_code == expected
    assert len(calls) == (0 if expected == 403 else 1)
