"""Automated tests for the first IntelSOC endpoint."""
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_returns_success():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "intelsoc-backend",
    }


def test_api_docs_available():
    response = client.get("/openapi.json")
    assert response.status_code == 200
    assert "/api/v1/health" in response.json()["paths"]
