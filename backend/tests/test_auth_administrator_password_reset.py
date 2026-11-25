from datetime import datetime, timezone, timedelta
from unittest.mock import Mock
from uuid import uuid4

import pytest
import psycopg

from fastapi.testclient import TestClient

from app.main import app
from app.api import rbac
from app.api.routes import user_management as route

from app.services import (
    auth_password_recovery_service as service,
)

from app.services.auth_rate_limit_service import (
    RecoveryRateLimitExceeded,
    ProvisioningRateLimitExceeded,
    RateLimitUnavailable,
)

from app.services.user_management_service import (
    UserManagementForbidden,
)


ORIGIN = "https://localhost:8443"
HEADERS = {"Origin": ORIGIN}

ADMIN_ID = uuid4()
TARGET_ID = uuid4()

EMAIL = "viewer@example.com"
TOKEN = "A" * 43

URL = f"/api/v1/users/{TARGET_ID}/reset-password"


@pytest.fixture
def delivery_result():

    return {
        "user_id": TARGET_ID,
        "reset_expires_at": (
            datetime.now(timezone.utc)
            + timedelta(minutes=30)
        ),
        "email_delivery": "submitted",
        "audit_recorded": True,
    }


@pytest.fixture
def api_dependencies(monkeypatch, delivery_result):

    monkeypatch.setenv(
        "INTELSOC_DASHBOARD_ORIGIN",
        ORIGIN,
    )

    reset = Mock(return_value=delivery_result)

    monkeypatch.setattr(
        route,
        "request_administrator_password_reset",
        reset,
    )

    user = {
        "user_id": ADMIN_ID,
        "username": "admin_test",
        "email": "admin@example.com",
        "role": "administrator",
        "status": "active",
    }

    def authenticated_user():
        return user

    app.dependency_overrides[
        rbac.get_authenticated_user
    ] = authenticated_user

    try:

        with TestClient(
            app,
            base_url=ORIGIN,
        ) as client:

            yield client, reset, user

    finally:

        app.dependency_overrides.pop(
            rbac.get_authenticated_user,
            None,
        )


def test_administrator_reset_success(api_dependencies):

    client, reset, user = api_dependencies

    response = client.post(URL, headers=HEADERS)

    assert response.status_code == 200

    result = response.json()

    assert result["user_id"] == str(TARGET_ID)
    assert result["email_delivery"] == "submitted"
    assert result["audit_recorded"] is True

    assert "reset_token" not in result
    assert "token_hash" not in result
    assert "password" not in result

    reset.assert_called_once()

    kwargs = reset.call_args.kwargs

    assert kwargs["user_id"] == TARGET_ID
    assert kwargs["actor_user_id"] == ADMIN_ID


@pytest.mark.parametrize("role", [
    "viewer",
    "analyst",
])
def test_unauthorized_role(api_dependencies, role):

    client, reset, user = api_dependencies

    user["role"] = role

    response = client.post(URL, headers=HEADERS)

    assert response.status_code == 403

    reset.assert_not_called()


def test_unauthenticated_request(api_dependencies):

    client, reset, user = api_dependencies

    app.dependency_overrides.pop(
        rbac.get_authenticated_user,
        None,
    )

    response = client.post(URL, headers=HEADERS)

    assert response.status_code == 401

    reset.assert_not_called()


@pytest.mark.parametrize("exception,expected", [
    (service.PasswordResetUserNotFound(), 404),
    (service.PasswordResetNotAllowed(), 409),
    (RecoveryRateLimitExceeded(60), 429),
    (ProvisioningRateLimitExceeded(60), 429),
    (RateLimitUnavailable("Redis unavailable"), 503),
    (UserManagementForbidden(), 403),
    (service.EmailConfigurationError("Invalid config"), 503),
    (psycopg.OperationalError("Database unavailable"), 503),
])
def test_administrator_reset_errors(
    api_dependencies,
    exception,
    expected,
):

    client, reset, user = api_dependencies

    reset.side_effect = exception

    response = client.post(URL, headers=HEADERS)

    assert response.status_code == expected

    if expected == 429:
        assert response.headers["Retry-After"] == "60"


def test_unconfirmed_email_delivery(api_dependencies):

    client, reset, user = api_dependencies

    reset.return_value["email_delivery"] = "unconfirmed"

    response = client.post(URL, headers=HEADERS)

    assert response.status_code == 200
    assert response.json()["email_delivery"] == "unconfirmed"


@pytest.fixture
def service_dependencies(monkeypatch, delivery_result):

    mocks = {
        "origin": Mock(),
        "smtp": Mock(),
        "provisioning": Mock(),
        "recovery": Mock(),
        "target": Mock(return_value={
            "user_id": TARGET_ID,
            "email": EMAIL,
            "status": "active",
        }),
        "issue": Mock(return_value={
            "user_id": TARGET_ID,
            "email": EMAIL,
            "username": "viewer_test",
            "reset_token": TOKEN,
        }),
        "delivery": Mock(return_value=delivery_result),
    }

    mappings = {
        "get_dashboard_origin": "origin",
        "get_smtp_config": "smtp",
        "enforce_provisioning_rate_limit": "provisioning",
        "enforce_password_recovery_rate_limit": "recovery",
        "get_user": "target",
        "issue_password_reset_token": "issue",
        "deliver_password_reset": "delivery",
    }

    for attribute, name in mappings.items():

        monkeypatch.setattr(
            service,
            attribute,
            mocks[name],
        )

    return mocks


def request_reset():

    return service.request_administrator_password_reset(
        user_id=TARGET_ID,
        actor_user_id=ADMIN_ID,
        source_ip="192.0.2.10",
    )


def test_administrator_orchestration(service_dependencies):

    mocks = service_dependencies

    result = request_reset()

    assert result["email_delivery"] == "submitted"
    assert TOKEN not in str(result)

    mocks["provisioning"].assert_called_once_with(
        actor_user_id=ADMIN_ID,
        user_id=TARGET_ID,
    )

    mocks["recovery"].assert_called_once_with(
        email=EMAIL,
        source_ip="192.0.2.10",
    )

    mocks["issue"].assert_called_once_with(
        user_id=TARGET_ID,
        actor_user_id=ADMIN_ID,
        source_ip="192.0.2.10",
    )

    mocks["delivery"].assert_called_once_with(
        issued_token=mocks["issue"].return_value,
        actor_user_id=ADMIN_ID,
        source_ip="192.0.2.10",
    )


def test_unknown_target(service_dependencies):

    service_dependencies["target"].return_value = None

    with pytest.raises(service.PasswordResetUserNotFound):
        request_reset()

    service_dependencies["issue"].assert_not_called()
    service_dependencies["delivery"].assert_not_called()


@pytest.mark.parametrize("status", [
    "invited",
    "suspended",
    "deactivated",
])
def test_inactive_target(service_dependencies, status):

    service_dependencies["target"].return_value[
        "status"
    ] = status

    with pytest.raises(service.PasswordResetNotAllowed):
        request_reset()

    service_dependencies["issue"].assert_not_called()
    service_dependencies["delivery"].assert_not_called()


@pytest.mark.parametrize("dependency,exception", [
    ("provisioning", ProvisioningRateLimitExceeded(60)),
    ("recovery", RecoveryRateLimitExceeded(60)),
    ("recovery", RateLimitUnavailable("Redis unavailable")),
    ("origin", service.EmailConfigurationError("Invalid origin")),
    ("smtp", service.EmailConfigurationError("Invalid SMTP")),
])
def test_recovery_preconditions(
    service_dependencies,
    dependency,
    exception,
):

    service_dependencies[dependency].side_effect = exception

    with pytest.raises(type(exception)):
        request_reset()

    service_dependencies["issue"].assert_not_called()
    service_dependencies["delivery"].assert_not_called()


def test_transactional_authorization_failure(
    service_dependencies,
):

    service_dependencies["issue"].side_effect = (
        UserManagementForbidden()
    )

    with pytest.raises(UserManagementForbidden):
        request_reset()

    service_dependencies["delivery"].assert_not_called()


@pytest.mark.parametrize("headers", [
    {},
    {"Origin": "https://untrusted.example.com"},
    {"Origin": "http://localhost:8443"},
])
def test_untrusted_origin(monkeypatch, headers):

    from app.api.routes.auth import SESSION_COOKIE

    monkeypatch.setenv(
        "INTELSOC_DASHBOARD_ORIGIN",
        ORIGIN,
    )

    reset = Mock()

    monkeypatch.setattr(
        route,
        "request_administrator_password_reset",
        reset,
    )

    session_validator = Mock(return_value={
        "user_id": ADMIN_ID,
        "role": "administrator",
        "status": "active",
    })

    monkeypatch.setattr(
        rbac,
        "validate_session",
        session_validator,
    )

    with TestClient(app, base_url=ORIGIN) as client:

        client.cookies.set(SESSION_COOKIE, TOKEN)

        response = client.post(URL, headers=headers)

        assert response.status_code == 403

    reset.assert_not_called()
