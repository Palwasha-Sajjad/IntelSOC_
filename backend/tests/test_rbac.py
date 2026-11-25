from unittest.mock import patch
from uuid import uuid4

import psycopg
import pytest

from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient

from app.api.rbac import (
    require_viewer,
    require_analyst,
    require_administrator,
)

from app.api.routes.auth import SESSION_COOKIE
from app.services.auth_session_service import InvalidSession


ORIGIN = "https://intelsoc.test"
TOKEN = "a" * 43

app = FastAPI()


@app.get("/viewer")
def viewer_route(user=Depends(require_viewer)):
    return {"role": user["role"]}


@app.get("/analyst")
def analyst_route(user=Depends(require_analyst)):
    return {"role": user["role"]}


@app.get("/administrator")
def administrator_route(user=Depends(require_administrator)):
    return {"role": user["role"]}


@app.patch("/administrator")
def administrator_write(user=Depends(require_administrator)):
    return {"status": "success"}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("INTELSOC_DASHBOARD_ORIGIN", ORIGIN)

    with TestClient(app, base_url=ORIGIN) as test_client:
        yield test_client


def make_user(role, status="active"):
    return {
        "user_id": uuid4(),
        "username": "test_user",
        "email": "test@example.com",
        "role": role,
        "status": status,
    }


@pytest.mark.parametrize("role,endpoint,expected", [
    ("viewer", "/viewer", 200),
    ("viewer", "/analyst", 403),
    ("viewer", "/administrator", 403),
    ("analyst", "/viewer", 200),
    ("analyst", "/analyst", 200),
    ("analyst", "/administrator", 403),
    ("administrator", "/viewer", 200),
    ("administrator", "/analyst", 200),
    ("administrator", "/administrator", 200),
])
def test_role_permissions(client, role, endpoint, expected):
    client.cookies.set(SESSION_COOKIE, TOKEN)

    with patch(
        "app.api.rbac.validate_session",
        return_value=make_user(role),
    ):
        response = client.get(endpoint)

    assert response.status_code == expected


@pytest.mark.parametrize("endpoint", [
    "/viewer",
    "/analyst",
    "/administrator",
])
def test_unauthenticated_access(client, endpoint):
    with patch(
        "app.api.rbac.validate_session",
        side_effect=InvalidSession(),
    ) as validate:
        response = client.get(endpoint)

    assert response.status_code == 401
    validate.assert_called_once_with(None)


@pytest.mark.parametrize("status", [
    "invited",
    "suspended",
    "deactivated",
])
def test_inactive_account_rejected(client, status):
    client.cookies.set(SESSION_COOKIE, TOKEN)

    with patch(
        "app.api.rbac.validate_session",
        return_value=make_user("administrator", status),
    ):
        response = client.get("/administrator")

    assert response.status_code == 401


def test_unknown_role_rejected(client):
    client.cookies.set(SESSION_COOKIE, TOKEN)

    with patch(
        "app.api.rbac.validate_session",
        return_value=make_user("unknown_role"),
    ):
        response = client.get("/viewer")

    assert response.status_code == 403


def test_invalid_session_rejected(client):
    client.cookies.set(SESSION_COOKIE, TOKEN)

    with patch(
        "app.api.rbac.validate_session",
        side_effect=InvalidSession(),
    ):
        response = client.get("/administrator")

    assert response.status_code == 401


def test_database_failure_blocks_access(client):
    client.cookies.set(SESSION_COOKIE, TOKEN)

    with patch(
        "app.api.rbac.validate_session",
        side_effect=psycopg.OperationalError(),
    ):
        response = client.get("/administrator")

    assert response.status_code == 503


def test_legacy_admin_key_cannot_bypass_rbac(client):
    with patch(
        "app.api.rbac.validate_session",
        side_effect=InvalidSession(),
    ):
        response = client.get(
            "/administrator",
            headers={
                "X-IntelSOC-Admin-Key": "test-key",
            },
        )

    assert response.status_code == 401


@pytest.mark.parametrize("origin", [
    None,
    "https://untrusted.example.com",
    "http://intelsoc.test",
    "null",
])
def test_write_csrf_protection(client, origin):
    client.cookies.set(SESSION_COOKIE, TOKEN)

    headers = {"Origin": origin} if origin else {}

    with patch(
        "app.api.rbac.validate_session",
        return_value=make_user("administrator"),
    ) as validate:
        response = client.patch(
            "/administrator",
            headers=headers,
        )

    assert response.status_code == 403
    validate.assert_not_called()


def test_administrator_write_allowed(client):
    client.cookies.set(SESSION_COOKIE, TOKEN)

    with patch(
        "app.api.rbac.validate_session",
        return_value=make_user("administrator"),
    ):
        response = client.patch(
            "/administrator",
            headers={"Origin": ORIGIN},
        )

    assert response.status_code == 200


@pytest.mark.parametrize("role", ["viewer", "analyst"])
def test_unauthorized_write_rejected(client, role):
    client.cookies.set(SESSION_COOKIE, TOKEN)

    with patch(
        "app.api.rbac.validate_session",
        return_value=make_user(role),
    ):
        response = client.patch(
            "/administrator",
            headers={"Origin": ORIGIN},
        )

    assert response.status_code == 403


def test_authenticated_response_not_cached(client):
    client.cookies.set(SESSION_COOKIE, TOKEN)

    with patch(
        "app.api.rbac.validate_session",
        return_value=make_user("viewer"),
    ):
        response = client.get("/viewer")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
