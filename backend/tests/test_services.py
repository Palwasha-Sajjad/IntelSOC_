from unittest.mock import MagicMock

import psycopg
from fastapi.testclient import TestClient

from app.main import app
from app.api.routes import services


client = TestClient(app)


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

    response = client.get("/api/v1/services/status")

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

    response = client.get("/api/v1/services/status")

    assert response.status_code == 503
    assert response.json()["status"] == "unavailable"
    assert response.json()["postgresql"] == "disconnected"
    assert response.json()["redis"] == "connected"
