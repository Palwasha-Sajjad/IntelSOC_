from datetime import datetime, timezone
from uuid import uuid4
from unittest.mock import patch

import pytest
import psycopg

from fastapi.testclient import TestClient

from app.main import app
from app.api.routes.auth import SESSION_COOKIE

from app.services.auth_session_service import (
    InvalidCredentials,
    InvalidSession,
    AuthenticationBusy,
)

from app.services.auth_rate_limit_service import (
    LoginRateLimitExceeded,
    RateLimitUnavailable,
)


ORIGIN = "https://intelsoc.test"
TOKEN = "a" * 43
USER_ID = uuid4()

USER = {
    "user_id": USER_ID,
    "username": "test_admin",
    "email": "admin@example.com",
    "role": "administrator",
    "status": "active",
}

CREDENTIALS = {
    "email": "admin@example.com",
    "password": "IntelSOC-Test-Password",
}

LOGIN_RESULT = {
    "session_id": uuid4(),
    "session_token": TOKEN,
    "expires_at": datetime.now(timezone.utc),
    "user": USER,
}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv(
        "INTELSOC_DASHBOARD_ORIGIN",
        ORIGIN,
    )

    with TestClient(app, base_url=ORIGIN) as test_client:
        yield test_client


def login_request(client):
    return client.post(
        "/api/v1/auth/login",
        json=CREDENTIALS,
        headers={"Origin": ORIGIN},
    )


def test_successful_login(client):
    with patch(
        "app.api.routes.auth.authenticate_user",
        return_value=LOGIN_RESULT,
    ):
        response = login_request(client)

    assert response.status_code == 200
    assert response.json()["user"]["role"] == "administrator"
    assert response.headers["cache-control"] == "no-store"


def test_secure_cookie(client):
    with patch(
        "app.api.routes.auth.authenticate_user",
        return_value=LOGIN_RESULT,
    ):
        response = login_request(client)

    cookie = response.headers["set-cookie"].lower()

    assert SESSION_COOKIE.lower() in cookie
    assert "httponly" in cookie
    assert "secure" in cookie
    assert "samesite=strict" in cookie
    assert "max-age=28800" in cookie
    assert "path=/" in cookie
    assert "domain=" not in cookie


def test_session_token_not_exposed_in_json(client):
    with patch(
        "app.api.routes.auth.authenticate_user",
        return_value=LOGIN_RESULT,
    ):
        response = login_request(client)

    assert TOKEN not in response.text
    assert "session_token" not in response.json()
    assert "session_id" not in response.json()


@pytest.mark.parametrize("origin", [
    None,
    "https://untrusted.example.com",
    "http://intelsoc.test",
    "null",
])
def test_login_csrf_protection(client, origin):
    headers = {"Origin": origin} if origin else {}

    with patch(
        "app.api.routes.auth.authenticate_user"
    ) as authenticate:
        response = client.post(
            "/api/v1/auth/login",
            json=CREDENTIALS,
            headers=headers,
        )

    assert response.status_code == 403
    authenticate.assert_not_called()


def test_missing_origin_configuration(client, monkeypatch):
    monkeypatch.delenv(
        "INTELSOC_DASHBOARD_ORIGIN",
        raising=False,
    )

    response = login_request(client)

    assert response.status_code == 503


@pytest.mark.parametrize("payload", [
    {},
    {"email": "", "password": "test"},
    {"email": "admin@example.com", "password": ""},
    {"email": "a" * 255, "password": "test"},
    {"email": "admin@example.com", "password": "a" * 129},
])
def test_invalid_login_payload(client, payload):
    response = client.post(
        "/api/v1/auth/login",
        json=payload,
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 422


def test_invalid_credentials(client):
    with patch(
        "app.api.routes.auth.authenticate_user",
        side_effect=InvalidCredentials(),
    ):
        response = login_request(client)

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password"
    assert "set-cookie" not in response.headers


def test_rate_limit_response(client):
    with patch(
        "app.api.routes.auth.authenticate_user",
        side_effect=LoginRateLimitExceeded(45),
    ):
        response = login_request(client)

    assert response.status_code == 429
    assert response.headers["retry-after"] == "45"


@pytest.mark.parametrize("error", [
    RateLimitUnavailable(),
    AuthenticationBusy(),
    psycopg.OperationalError(),
])
def test_authentication_unavailable(client, error):
    with patch(
        "app.api.routes.auth.authenticate_user",
        side_effect=error,
    ):
        response = login_request(client)

    assert response.status_code == 503
    assert "set-cookie" not in response.headers


def test_authenticated_identity(client):
    session = {
        **USER,
        "session_id": uuid4(),
        "expires_at": datetime.now(timezone.utc),
    }

    client.cookies.set(SESSION_COOKIE, TOKEN)

    with patch(
        "app.api.routes.auth.validate_session",
        return_value=session,
    ) as validate:
        response = client.get("/api/v1/auth/me")

    assert response.status_code == 200
    assert response.json()["role"] == "administrator"
    assert "session_id" not in response.json()
    assert response.headers["cache-control"] == "no-store"
    validate.assert_called_once_with(TOKEN)


def test_invalid_session(client):
    with patch(
        "app.api.routes.auth.validate_session",
        side_effect=InvalidSession(),
    ):
        response = client.get("/api/v1/auth/me")

    assert response.status_code == 401


def test_successful_logout(client):
    client.cookies.set(SESSION_COOKIE, TOKEN)

    with patch(
        "app.api.routes.auth.revoke_session",
        return_value=True,
    ) as revoke:
        response = client.post(
            "/api/v1/auth/logout",
            headers={"Origin": ORIGIN},
        )

    assert response.status_code == 200
    assert response.json()["status"] == "logged_out"
    assert "max-age=0" in response.headers["set-cookie"].lower()
    revoke.assert_called_once()


def test_logout_csrf_protection(client):
    client.cookies.set(SESSION_COOKIE, TOKEN)

    with patch(
        "app.api.routes.auth.revoke_session"
    ) as revoke:
        response = client.post(
            "/api/v1/auth/logout",
            headers={"Origin": "https://untrusted.example.com"},
        )

    assert response.status_code == 403
    revoke.assert_not_called()


def test_repeated_logout(client):
    response = client.post(
        "/api/v1/auth/logout",
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 200


def test_registered_api_operations():
    schema = app.openapi()

    operations = sum(
        1
        for methods in schema["paths"].values()
        for method in methods
        if method in {
            "get", "post", "put", "patch", "delete",
        }
    )

    assert operations == 31

def test_password_not_exposed_in_validation_error(client):
    sensitive_password = "IntelSOC-Sensitive-Test-Only-" * 6

    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": "test@example.com",
            "password": sensitive_password,
        },
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 422
    assert sensitive_password not in response.text
    assert response.json() == {
        "detail": "Invalid authentication request"
    }
    assert response.headers["cache-control"] == "no-store"


def test_email_not_exposed_in_validation_error(client):
    sensitive_email = "private-test-email-" * 20

    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": sensitive_email,
            "password": "IntelSOC-Test-Password",
        },
        headers={"Origin": ORIGIN},
    )

    assert response.status_code == 422
    assert sensitive_email not in response.text


def test_malformed_json_does_not_expose_credentials(client):
    sensitive_password = "IntelSOC-Private-Test-Password"

    response = client.post(
        "/api/v1/auth/login",
        content='{"password": "' + sensitive_password,
        headers={
            "Origin": ORIGIN,
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 422
    assert sensitive_password not in response.text
    assert response.headers["cache-control"] == "no-store"
