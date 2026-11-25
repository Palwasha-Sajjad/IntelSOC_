from unittest.mock import Mock

import psycopg
import pytest

from fastapi.testclient import TestClient

from app.main import app
from app.api.routes import auth

from app.services.auth_activation_service import (
    InvalidInvitation,
)

from app.services.auth_rate_limit_service import (
    ActivationRateLimitExceeded,
    RateLimitUnavailable,
)


ENDPOINT = "/api/v1/auth/activate"
ORIGIN = "https://localhost:8443"

TOKEN = "a" * 43
PASSWORD = "IntelSOC-Test-Password-2026!"

HEADERS = {"Origin": ORIGIN}

PAYLOAD = {
    "invitation_token": TOKEN,
    "password": PASSWORD,
}


@pytest.fixture
def client(monkeypatch):

    monkeypatch.setenv(
        "INTELSOC_DASHBOARD_ORIGIN",
        ORIGIN,
    )

    with TestClient(
        app,
        base_url=ORIGIN,
    ) as test_client:
        yield test_client


@pytest.fixture
def dependencies(monkeypatch):

    activate = Mock(return_value={
        "status": "active",
        "role": "viewer",
        "password_hash": "sensitive-password-hash",
    })

    limiter = Mock()

    slots = Mock()
    slots.acquire.return_value = True

    monkeypatch.setattr(
        auth, "activate_account", activate
    )

    monkeypatch.setattr(
        auth, "enforce_activation_rate_limit", limiter
    )

    monkeypatch.setattr(
        auth, "PASSWORD_VERIFICATION_SLOTS", slots
    )

    return activate, limiter, slots


def test_successful_activation(client, dependencies):

    activate, limiter, slots = dependencies

    response = client.post(
        ENDPOINT,
        headers=HEADERS,
        json=PAYLOAD,
    )

    assert response.status_code == 200
    assert response.json()["status"] == "activated"
    assert response.headers["Cache-Control"] == "no-store"

    activate.assert_called_once()
    limiter.assert_called_once()

    args = activate.call_args.kwargs

    assert args["invitation_token"] == TOKEN
    assert args["password"] == PASSWORD

    slots.acquire.assert_called_once_with(blocking=False)
    slots.release.assert_called_once()


def test_no_automatic_session(client, dependencies):

    response = client.post(
        ENDPOINT,
        headers=HEADERS,
        json=PAYLOAD,
    )

    assert response.status_code == 200
    assert "set-cookie" not in response.headers
    assert "session_token" not in response.json()


def test_sensitive_response_protection(client, dependencies):

    response = client.post(
        ENDPOINT,
        headers=HEADERS,
        json=PAYLOAD,
    )

    assert response.status_code == 200

    assert TOKEN not in response.text
    assert PASSWORD not in response.text
    assert "sensitive-password-hash" not in response.text

    assert set(response.json()) == {
        "status",
        "message",
    }


@pytest.mark.parametrize("origin", [
    None,
    "https://untrusted.example.com",
    "http://localhost:8443",
    "null",
])
def test_origin_protection(
    client, dependencies, origin
):

    headers = {}

    if origin is not None:
        headers["Origin"] = origin

    response = client.post(
        ENDPOINT,
        headers=headers,
        json=PAYLOAD,
    )

    assert response.status_code == 403

    activate, limiter, slots = dependencies

    activate.assert_not_called()
    limiter.assert_not_called()
    slots.acquire.assert_not_called()


@pytest.mark.parametrize("payload", [
    {},
    {**PAYLOAD, "invitation_token": "short"},
    {**PAYLOAD, "invitation_token": "a" * 44},
    {**PAYLOAD, "invitation_token": "!" * 43},
    {**PAYLOAD, "password": "short"},
    {**PAYLOAD, "password": "a" * 129},
    {"invitation_token": TOKEN},
    {"password": PASSWORD},
])
def test_invalid_payload(
    client, dependencies, payload
):

    response = client.post(
        ENDPOINT,
        headers=HEADERS,
        json=payload,
    )

    assert response.status_code == 422
    assert response.json() == {
        "detail": "Invalid authentication request"
    }

    assert TOKEN not in response.text
    assert PASSWORD not in response.text

    activate, limiter, slots = dependencies

    activate.assert_not_called()
    limiter.assert_not_called()
    slots.acquire.assert_not_called()


def test_invalid_invitation(client, dependencies):

    activate, limiter, slots = dependencies

    activate.side_effect = InvalidInvitation(
        "Sensitive token information"
    )

    response = client.post(
        ENDPOINT,
        headers=HEADERS,
        json=PAYLOAD,
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "Invalid or expired invitation"
    )

    assert "Sensitive token information" not in response.text
    assert response.headers["Cache-Control"] == "no-store"

    slots.release.assert_called_once()


def test_password_policy_rejection(client, dependencies):

    activate, limiter, slots = dependencies

    activate.side_effect = ValueError(
        "Sensitive password information"
    )

    response = client.post(
        ENDPOINT,
        headers=HEADERS,
        json=PAYLOAD,
    )

    assert response.status_code == 422
    assert "Sensitive password information" not in response.text

    slots.release.assert_called_once()


def test_activation_rate_limit(client, dependencies):

    activate, limiter, slots = dependencies

    limiter.side_effect = ActivationRateLimitExceeded(60)

    response = client.post(
        ENDPOINT,
        headers=HEADERS,
        json=PAYLOAD,
    )

    assert response.status_code == 429
    assert response.headers["Retry-After"] == "60"
    assert response.headers["Cache-Control"] == "no-store"

    activate.assert_not_called()
    slots.acquire.assert_not_called()


def test_redis_failure(client, dependencies):

    activate, limiter, slots = dependencies

    limiter.side_effect = RateLimitUnavailable(
        "Sensitive Redis information"
    )

    response = client.post(
        ENDPOINT,
        headers=HEADERS,
        json=PAYLOAD,
    )

    assert response.status_code == 503
    assert "Sensitive Redis information" not in response.text

    activate.assert_not_called()
    slots.acquire.assert_not_called()


def test_password_hashing_capacity(client, dependencies):

    activate, limiter, slots = dependencies

    slots.acquire.return_value = False

    response = client.post(
        ENDPOINT,
        headers=HEADERS,
        json=PAYLOAD,
    )

    assert response.status_code == 503

    activate.assert_not_called()
    slots.release.assert_not_called()


@pytest.mark.parametrize("error", [
    psycopg.OperationalError("Sensitive database error"),
    OSError("Sensitive connection error"),
    KeyError("Sensitive configuration error"),
])
def test_storage_failure(client, dependencies, error):

    activate, limiter, slots = dependencies

    activate.side_effect = error

    response = client.post(
        ENDPOINT,
        headers=HEADERS,
        json=PAYLOAD,
    )

    assert response.status_code == 503
    assert "Sensitive" not in response.text
    assert response.headers["Cache-Control"] == "no-store"

    slots.release.assert_called_once()
