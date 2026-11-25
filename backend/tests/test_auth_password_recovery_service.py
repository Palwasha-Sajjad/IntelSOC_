from datetime import datetime, timezone
from uuid import uuid4
from unittest.mock import Mock

import pytest
import psycopg

from app.services import (
    auth_password_recovery_service as service,
)

from app.services.auth_rate_limit_service import (
    RecoveryRateLimitExceeded,
    RateLimitUnavailable,
)


EMAIL = "viewer@example.com"
USERNAME = "viewer_test"
TOKEN = "A" * 43
SOURCE_IP = "192.0.2.10"


@pytest.fixture
def issued_token():

    return {
        "token_id": uuid4(),
        "user_id": uuid4(),
        "username": USERNAME,
        "email": EMAIL,
        "role": "viewer",
        "reset_token": TOKEN,
        "expires_at": datetime.now(timezone.utc),
    }


@pytest.fixture
def dependencies(monkeypatch, issued_token):

    mocks = {
        "rate_limit": Mock(),
        "origin": Mock(
            return_value="https://localhost:8443"
        ),
        "smtp": Mock(),
        "issue": Mock(return_value=issued_token),
        "send": Mock(return_value=True),
        "audit": Mock(),
    }

    mappings = {
        "enforce_password_recovery_rate_limit": "rate_limit",
        "get_dashboard_origin": "origin",
        "get_smtp_config": "smtp",
        "issue_password_reset_token": "issue",
        "send_password_reset_email": "send",
        "record_recovery_email_outcome": "audit",
    }

    for attribute, name in mappings.items():

        monkeypatch.setattr(
            service,
            attribute,
            mocks[name],
        )

    return mocks


def test_successful_recovery(dependencies, issued_token):

    result = service.request_password_recovery(
        email=EMAIL,
        source_ip=SOURCE_IP,
    )

    assert result == {
        "message": service.GENERIC_RECOVERY_MESSAGE
    }

    dependencies["rate_limit"].assert_called_once_with(
        email=EMAIL,
        source_ip=SOURCE_IP,
    )

    dependencies["issue"].assert_called_once_with(
        email=EMAIL,
        source_ip=SOURCE_IP,
    )

    dependencies["send"].assert_called_once_with(
        recipient=EMAIL,
        username=USERNAME,
        reset_token=TOKEN,
    )

    dependencies["audit"].assert_called_once_with(
        user_id=issued_token["user_id"],
        actor_user_id=None,
        source_ip=SOURCE_IP,
        outcome="success",
    )

    assert TOKEN not in str(result)


def test_email_normalization(dependencies):

    service.request_password_recovery(
        email="  VIEWER@EXAMPLE.COM  ",
        source_ip=SOURCE_IP,
    )

    dependencies["issue"].assert_called_once_with(
        email=EMAIL,
        source_ip=SOURCE_IP,
    )


@pytest.mark.parametrize("exception", [
    service.PasswordResetUserNotFound,
    service.PasswordResetNotAllowed,
])
def test_unknown_or_ineligible_account(
    dependencies,
    exception,
):

    dependencies["issue"].side_effect = exception()

    result = service.request_password_recovery(
        email=EMAIL,
        source_ip=SOURCE_IP,
    )

    assert result == {
        "message": service.GENERIC_RECOVERY_MESSAGE
    }

    dependencies["rate_limit"].assert_called_once()
    dependencies["send"].assert_not_called()
    dependencies["audit"].assert_not_called()


@pytest.mark.parametrize("exception", [
    RecoveryRateLimitExceeded(60),
    RateLimitUnavailable("Redis unavailable"),
])
def test_rate_limit_failure(dependencies, exception):

    dependencies["rate_limit"].side_effect = exception

    with pytest.raises(type(exception)):

        service.request_password_recovery(
            email=EMAIL,
            source_ip=SOURCE_IP,
        )

    dependencies["issue"].assert_not_called()
    dependencies["send"].assert_not_called()


@pytest.mark.parametrize("email", [
    "",
    "invalid-email",
    "viewer@",
    "viewer@example",
    "viewer\\n@example.com",
])
def test_invalid_email(dependencies, email):

    with pytest.raises(ValueError):

        service.request_password_recovery(
            email=email,
            source_ip=SOURCE_IP,
        )

    dependencies["issue"].assert_not_called()
    dependencies["send"].assert_not_called()


@pytest.mark.parametrize("dependency", [
    "origin",
    "smtp",
])
def test_configuration_preflight_failure(
    dependencies,
    dependency,
):

    dependencies[dependency].side_effect = (
        service.EmailConfigurationError(
            "Invalid configuration"
        )
    )

    with pytest.raises(service.EmailConfigurationError):

        service.request_password_recovery(
            email=EMAIL,
            source_ip=SOURCE_IP,
        )

    dependencies["issue"].assert_not_called()
    dependencies["send"].assert_not_called()


@pytest.mark.parametrize("exception", [
    service.EmailDeliveryError("SMTP failure"),
    service.EmailConfigurationError("Configuration failure"),
    OSError("Connection failure"),
    ValueError("Invalid email payload"),
])
def test_delivery_failure(
    dependencies,
    issued_token,
    exception,
):

    dependencies["send"].side_effect = exception

    result = service.request_password_recovery(
        email=EMAIL,
        source_ip=SOURCE_IP,
    )

    assert result == {
        "message": service.GENERIC_RECOVERY_MESSAGE
    }

    dependencies["audit"].assert_called_once_with(
        user_id=issued_token["user_id"],
        actor_user_id=None,
        source_ip=SOURCE_IP,
        outcome="failure",
    )


def test_unconfirmed_delivery(
    dependencies,
    issued_token,
):

    dependencies["send"].return_value = False

    result = service.deliver_password_reset(
        issued_token=issued_token,
    )

    assert result["email_delivery"] == "unconfirmed"
    assert result["audit_recorded"] is True
    assert TOKEN not in str(result)


def test_delivery_success(
    dependencies,
    issued_token,
):

    result = service.deliver_password_reset(
        issued_token=issued_token,
    )

    assert result["email_delivery"] == "submitted"
    assert result["audit_recorded"] is True
    assert result["user_id"] == issued_token["user_id"]
    assert "reset_token" not in result
    assert "token_hash" not in result


def test_audit_failure(
    dependencies,
    issued_token,
):

    dependencies["audit"].side_effect = (
        psycopg.OperationalError("Database unavailable")
    )

    result = service.deliver_password_reset(
        issued_token=issued_token,
    )

    assert result["email_delivery"] == "submitted"
    assert result["audit_recorded"] is False


def test_administrator_delivery_attribution(
    dependencies,
    issued_token,
):

    actor = uuid4()

    service.deliver_password_reset(
        issued_token=issued_token,
        actor_user_id=actor,
        source_ip=SOURCE_IP,
    )

    dependencies["audit"].assert_called_once_with(
        user_id=issued_token["user_id"],
        actor_user_id=actor,
        source_ip=SOURCE_IP,
        outcome="success",
    )


def test_token_issuance_failure(dependencies):

    dependencies["issue"].side_effect = (
        psycopg.OperationalError("Database unavailable")
    )

    with pytest.raises(psycopg.OperationalError):

        service.request_password_recovery(
            email=EMAIL,
            source_ip=SOURCE_IP,
        )

    dependencies["send"].assert_not_called()


def test_processing_order(dependencies, issued_token):

    calls = []

    for name in [
        "rate_limit",
        "origin",
        "smtp",
        "issue",
        "send",
        "audit",
    ]:

        value = dependencies[name].return_value

        def record(*args, _name=name, _value=value, **kwargs):
            calls.append(_name)
            return _value

        dependencies[name].side_effect = record

    service.request_password_recovery(
        email=EMAIL,
        source_ip=SOURCE_IP,
    )

    assert calls == [
        "rate_limit",
        "origin",
        "smtp",
        "issue",
        "send",
        "audit",
    ]
