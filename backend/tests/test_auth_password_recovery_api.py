from unittest.mock import Mock
from uuid import uuid4

import pytest
import psycopg

from fastapi.testclient import TestClient

from app.main import app
from app.api.routes import auth as route


ORIGIN = "https://localhost:8443"
HEADERS = {"Origin": ORIGIN}

FORGOT_URL = "/api/v1/auth/forgot-password"
RESET_URL = "/api/v1/auth/reset-password"

EMAIL = "viewer@example.com"
TOKEN = "A" * 43
PASSWORD = "Example-Secure-Password-2026"


@pytest.fixture
def client(monkeypatch):

    monkeypatch.setenv(
        "INTELSOC_DASHBOARD_ORIGIN",
        ORIGIN,
    )

    return TestClient(
        app,
        base_url=ORIGIN,
    )


@pytest.fixture
def dependencies(monkeypatch):

    mocks = {
        "recover": Mock(),
        "rate_limit": Mock(),
        "reset": Mock(return_value={
            "user_id": uuid4(),
            "username": "viewer_test",
            "email": EMAIL,
            "role": "viewer",
            "revoked_sessions": 3,
        }),
        "confirmation": Mock(return_value=True),
    }

    mappings = {
        "request_password_recovery": "recover",
        "enforce_password_reset_rate_limit": "rate_limit",
        "reset_password": "reset",
        "send_password_change_confirmation_email": "confirmation",
    }

    for attribute, name in mappings.items():
        monkeypatch.setattr(
            route,
            attribute,
            mocks[name],
        )

    return mocks


def test_forgot_password_success(client, dependencies):

    response = client.post(
        FORGOT_URL,
        headers=HEADERS,
        json={"email": EMAIL},
    )

    assert response.status_code == 202

    assert response.json() == {
        "message": route.GENERIC_RECOVERY_MESSAGE
    }

    assert response.headers["Cache-Control"] == "no-store"
    assert "set-cookie" not in response.headers

    dependencies["recover"].assert_called_once()

    assert (
        dependencies["recover"].call_args.kwargs["email"]
        == EMAIL
    )


def test_recovery_email_normalization(client, dependencies):

    response = client.post(
        FORGOT_URL,
        headers=HEADERS,
        json={"email": "  VIEWER@EXAMPLE.COM  "},
    )

    assert response.status_code == 202

    assert (
        dependencies["recover"].call_args.kwargs["email"]
        == EMAIL
    )


@pytest.mark.parametrize("exception", [
    route.RecoveryRateLimitExceeded(60),
    route.RateLimitUnavailable("Redis unavailable"),
    route.EmailConfigurationError("Invalid SMTP config"),
    route.EmailDeliveryError("SMTP failure"),
    psycopg.OperationalError("Database unavailable"),
])
def test_generic_recovery_failure_response(
    client,
    dependencies,
    exception,
):

    dependencies["recover"].side_effect = exception

    response = client.post(
        FORGOT_URL,
        headers=HEADERS,
        json={"email": EMAIL},
    )

    assert response.status_code == 202

    assert response.json() == {
        "message": route.GENERIC_RECOVERY_MESSAGE
    }


@pytest.mark.parametrize("email", [
    "",
    "invalid-email",
    "viewer@",
    "viewer@example",
    "a" * 255,
])
def test_invalid_recovery_email(client, dependencies, email):

    response = client.post(
        FORGOT_URL,
        headers=HEADERS,
        json={"email": email},
    )

    assert response.status_code == 422

    dependencies["recover"].assert_not_called()


@pytest.mark.parametrize("url,payload", [
    (FORGOT_URL, {"email": EMAIL}),
    (RESET_URL, {
        "reset_token": TOKEN,
        "password": PASSWORD,
    }),
])
@pytest.mark.parametrize("headers", [
    {},
    {"Origin": "https://untrusted.example.com"},
    {"Origin": "http://localhost:8443"},
])
def test_untrusted_origin(
    client,
    dependencies,
    url,
    payload,
    headers,
):

    response = client.post(
        url,
        headers=headers,
        json=payload,
    )

    assert response.status_code == 403

    dependencies["recover"].assert_not_called()
    dependencies["reset"].assert_not_called()


def test_recovery_capacity_limit(client, dependencies):

    acquired = 0

    try:

        for _ in range(4):

            assert route.RECOVERY_TASK_SLOTS.acquire(
                blocking=False
            )

            acquired += 1

        response = client.post(
            FORGOT_URL,
            headers=HEADERS,
            json={"email": EMAIL},
        )

        assert response.status_code == 503

        dependencies["recover"].assert_not_called()

    finally:

        for _ in range(acquired):
            route.RECOVERY_TASK_SLOTS.release()


def test_password_reset_success(client, dependencies):

    response = client.post(
        RESET_URL,
        headers=HEADERS,
        json={
            "reset_token": TOKEN,
            "password": PASSWORD,
        },
    )

    assert response.status_code == 200

    assert response.json()["status"] == "password_reset"
    assert response.headers["Cache-Control"] == "no-store"

    cookie = response.headers["set-cookie"].lower()

    assert "max-age=0" in cookie
    assert "httponly" in cookie
    assert "secure" in cookie

    assert TOKEN not in response.text
    assert PASSWORD not in response.text
    assert EMAIL not in response.text

    dependencies["rate_limit"].assert_called_once()
    dependencies["reset"].assert_called_once()

    dependencies["confirmation"].assert_called_once_with(
        recipient=EMAIL,
        username="viewer_test",
    )


@pytest.mark.parametrize("token,password", [
    ("invalid", PASSWORD),
    ("A" * 42, PASSWORD),
    ("A" * 44, PASSWORD),
    ("!" * 43, PASSWORD),
    (TOKEN, "short"),
    (TOKEN, "a" * 129),
])
def test_invalid_reset_payload(
    client,
    dependencies,
    token,
    password,
):

    response = client.post(
        RESET_URL,
        headers=HEADERS,
        json={
            "reset_token": token,
            "password": password,
        },
    )

    assert response.status_code == 422

    assert TOKEN not in response.text
    assert PASSWORD not in response.text

    dependencies["reset"].assert_not_called()
    dependencies["confirmation"].assert_not_called()


def test_invalid_or_consumed_token(client, dependencies):

    dependencies["reset"].side_effect = (
        route.InvalidPasswordResetToken()
    )

    response = client.post(
        RESET_URL,
        headers=HEADERS,
        json={
            "reset_token": TOKEN,
            "password": PASSWORD,
        },
    )

    assert response.status_code == 400

    dependencies["confirmation"].assert_not_called()


def test_reset_rate_limit(client, dependencies):

    dependencies["rate_limit"].side_effect = (
        route.ResetRateLimitExceeded(45)
    )

    response = client.post(
        RESET_URL,
        headers=HEADERS,
        json={
            "reset_token": TOKEN,
            "password": PASSWORD,
        },
    )

    assert response.status_code == 429
    assert response.headers["Retry-After"] == "45"

    dependencies["reset"].assert_not_called()
    dependencies["confirmation"].assert_not_called()


def test_reset_redis_failure(client, dependencies):

    dependencies["rate_limit"].side_effect = (
        route.RateLimitUnavailable("Redis unavailable")
    )

    response = client.post(
        RESET_URL,
        headers=HEADERS,
        json={
            "reset_token": TOKEN,
            "password": PASSWORD,
        },
    )

    assert response.status_code == 503

    dependencies["reset"].assert_not_called()
    dependencies["confirmation"].assert_not_called()


def test_reset_database_failure(client, dependencies):

    dependencies["reset"].side_effect = (
        psycopg.OperationalError("Database unavailable")
    )

    response = client.post(
        RESET_URL,
        headers=HEADERS,
        json={
            "reset_token": TOKEN,
            "password": PASSWORD,
        },
    )

    assert response.status_code == 503

    dependencies["confirmation"].assert_not_called()


def test_confirmation_failure_preserves_reset(
    client,
    dependencies,
):

    dependencies["confirmation"].side_effect = (
        route.EmailDeliveryError("SMTP failure")
    )

    response = client.post(
        RESET_URL,
        headers=HEADERS,
        json={
            "reset_token": TOKEN,
            "password": PASSWORD,
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "password_reset"


def test_recovery_task_slot_cleanup(client, dependencies):

    for _ in range(6):

        response = client.post(
            FORGOT_URL,
            headers=HEADERS,
            json={"email": EMAIL},
        )

        assert response.status_code == 202

    assert dependencies["recover"].call_count == 6
