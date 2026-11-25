from unittest.mock import MagicMock

import psycopg
from fastapi.testclient import TestClient

from app.main import app
from app.api.routes import services


import pytest

from app.api import rbac
from app.api.routes.auth import SESSION_COOKIE
from app.services.auth_session_service import InvalidSession


TOKEN = "e" * 43
HEADERS = {"Cookie": f"{SESSION_COOKIE}={TOKEN}"}

client = TestClient(app, base_url="https://intelsoc.test")


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


def test_services_ready(monkeypatch):
    # Simulate a working PostgreSQL connection
    pg = MagicMock()
    pg.__enter__.return_value = pg

    monkeypatch.setattr(
        services.psycopg,
        "connect",
        lambda **kwargs: pg
    )

    # Simulate a working Redis connection
    redis_client = MagicMock()
    redis_client.__enter__.return_value = redis_client
    redis_client.ping.return_value = True

    monkeypatch.setattr(
        services.redis,
        "Redis",
        lambda **kwargs: redis_client
    )

    response = client.get("/api/v1/services/status", headers=HEADERS)

    assert response.status_code == 200
    assert response.json()["status"] == "ready"
    assert response.json()["postgresql"] == "connected"
    assert response.json()["redis"] == "connected"


def test_postgresql_unavailable(monkeypatch):
    # Simulate PostgreSQL connection failure
    def fail_connection(**kwargs):
        raise psycopg.OperationalError("Database unavailable")

    monkeypatch.setattr(
        services.psycopg,
        "connect",
        fail_connection
    )

    # Redis is still working
    redis_client = MagicMock()
    redis_client.__enter__.return_value = redis_client
    redis_client.ping.return_value = True

    monkeypatch.setattr(
        services.redis,
        "Redis",
        lambda **kwargs: redis_client
    )

    response = client.get("/api/v1/services/status", headers=HEADERS)

    assert response.status_code == 503
    assert response.json()["status"] == "unavailable"
    assert response.json()["postgresql"] == "disconnected"
    assert response.json()["redis"] == "connected"


@pytest.mark.parametrize("role,expected", [
    ("viewer", 403),
    ("analyst", 403),
    ("administrator", 200),
])
def test_services_role_permissions(monkeypatch, role, expected):
    calls = []

    def validate(token):
        if token != TOKEN:
            raise InvalidSession()

        return {
            "role": role,
            "status": "active",
        }

    pg = MagicMock()
    pg.__enter__.return_value = pg

    def connect(**kwargs):
        calls.append("postgresql")
        return pg

    redis_client = MagicMock()
    redis_client.__enter__.return_value = redis_client
    redis_client.ping.return_value = True

    monkeypatch.setattr(rbac, "validate_session", validate)
    monkeypatch.setattr(services.psycopg, "connect", connect)
    monkeypatch.setattr(
        services.redis,
        "Redis",
        lambda **kwargs: redis_client,
    )

    response = client.get(
        "/api/v1/services/status",
        headers=HEADERS,
    )

    assert response.status_code == expected
    assert len(calls) == (1 if expected == 200 else 0)


@pytest.mark.parametrize("headers", [
    {},
    {"X-IntelSOC-Admin-Key": "admin-test-key"},
    {"X-IntelSOC-Key": "ingest-test-key"},
])
def test_services_rejects_unauthenticated_access(monkeypatch, headers):
    monkeypatch.setenv(
        "INTELSOC_ADMIN_API_KEY",
        "admin-test-key",
    )

    monkeypatch.setenv(
        "INTELSOC_INGEST_API_KEY",
        "ingest-test-key",
    )

    def fail(**kwargs):
        raise AssertionError("Unauthorized database access")

    monkeypatch.setattr(services.psycopg, "connect", fail)

    response = client.get(
        "/api/v1/services/status",
        headers=headers,
    )

    assert response.status_code == 401
