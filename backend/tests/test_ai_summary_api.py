"""Batch 6: admin-protected AI summary route (isolated, no PostgreSQL)."""
from datetime import datetime, timezone

import psycopg
from fastapi.testclient import TestClient

from app.api.routes import ai_analysis
from app.main import app

client = TestClient(app)
URL = "/api/v1/ai/summary"


def sample_summary():
    return {"model_version": "LAnoBERT-v0.2", "total": 4,
            "processed": 3, "failed": 1, "skipped": 0,
            "average_latency_ms": 90.25,
            "last_processed_at": datetime(2026, 11, 21, tzinfo=timezone.utc)}


def test_summary_requires_admin_before_database(monkeypatch):
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
    response = client.get(URL, headers={"X-IntelSOC-Admin-Key": "summary-admin"})
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
    response = client.get(URL, headers={"X-IntelSOC-Admin-Key": "summary-admin"})
    assert response.status_code == 503
    assert "secret-value" not in response.text


def test_summary_not_public_when_admin_unconfigured(monkeypatch):
    monkeypatch.delenv("INTELSOC_ADMIN_API_KEY", raising=False)
    assert client.get(URL).status_code == 503
