from datetime import datetime, timezone
from unittest.mock import Mock
from uuid import uuid4

import psycopg
import pytest

from app.services import auth_provisioning_service as service

from app.services.email_service import (
    EmailConfigurationError,
    EmailDeliveryError,
)

from app.services.user_management_service import (
    DuplicateUserError,
    UserManagementForbidden,
)


ADMIN_ID = uuid4()
USER_ID = uuid4()
TOKEN = "a" * 43
EXPIRY = datetime.now(timezone.utc)


@pytest.fixture
def dependencies(monkeypatch):

    mocks = {
        "get_dashboard_origin": Mock(
            return_value="https://localhost:8443"
        ),
        "get_smtp_config": Mock(return_value={}),
        "enforce_provisioning_rate_limit": Mock(),
        "create_user": Mock(return_value={
            "user_id": USER_ID,
            "username": "test_user",
            "email": "test@example.com",
            "role": "viewer",
            "status": "invited",
        }),
        "issue_invitation": Mock(return_value={
            "user_id": USER_ID,
            "username": "test_user",
            "email": "test@example.com",
            "role": "viewer",
            "invitation_token": TOKEN,
            "expires_at": EXPIRY,
        }),
        "send_invitation_email": Mock(return_value=True),
        "record_delivery_outcome": Mock(),
    }

    for name, mock in mocks.items():
        monkeypatch.setattr(service, name, mock)

    return mocks


def provision():
    return service.provision_user(
        username="test_user",
        email="test@example.com",
        role="viewer",
        actor_user_id=ADMIN_ID,
        source_ip="127.0.0.1",
    )


def resend():
    return service.deliver_invitation(
        user_id=USER_ID,
        actor_user_id=ADMIN_ID,
        source_ip="127.0.0.1",
    )


def test_successful_provisioning(dependencies):

    result = provision()

    assert result["user"]["status"] == "invited"
    assert result["email_delivery"] == "submitted"
    assert result["invitation_expires_at"] == EXPIRY
    assert result["audit_recorded"] is True

    dependencies["create_user"].assert_called_once()
    dependencies["issue_invitation"].assert_called_once()

    dependencies["send_invitation_email"].assert_called_once_with(
        recipient="test@example.com",
        username="test_user",
        role="viewer",
        invitation_token=TOKEN,
    )


def test_raw_token_not_exposed(dependencies):

    result = provision()

    assert TOKEN not in str(result)
    assert "invitation_token" not in result


def test_delivery_success_audit(dependencies):

    provision()

    dependencies["record_delivery_outcome"].assert_called_once_with(
        user_id=USER_ID,
        actor_user_id=ADMIN_ID,
        outcome="success",
        source_ip="127.0.0.1",
    )


@pytest.mark.parametrize("error", [
    EmailDeliveryError("SMTP failure"),
    EmailConfigurationError("Configuration failure"),
    ValueError("Invalid email data"),
])
def test_delivery_failure_recovery(dependencies, error):

    dependencies["send_invitation_email"].side_effect = error

    result = provision()

    assert result["user"]["status"] == "invited"
    assert result["email_delivery"] == "unconfirmed"
    assert result["audit_recorded"] is True
    assert TOKEN not in str(result)

    assert (
        dependencies["record_delivery_outcome"]
        .call_args.kwargs["outcome"]
        == "failure"
    )


def test_false_submission_result(dependencies):

    dependencies["send_invitation_email"].return_value = False

    result = provision()

    assert result["email_delivery"] == "unconfirmed"


@pytest.mark.parametrize("setting", [
    "get_dashboard_origin",
    "get_smtp_config",
])
def test_configuration_preflight(dependencies, setting):

    dependencies[setting].side_effect = EmailConfigurationError(
        "Invalid configuration"
    )

    with pytest.raises(EmailConfigurationError):
        provision()

    dependencies["create_user"].assert_not_called()
    dependencies["issue_invitation"].assert_not_called()
    dependencies["send_invitation_email"].assert_not_called()


def test_duplicate_account_blocks_delivery(dependencies):

    dependencies["create_user"].side_effect = DuplicateUserError()

    with pytest.raises(DuplicateUserError):
        provision()

    dependencies["issue_invitation"].assert_not_called()
    dependencies["send_invitation_email"].assert_not_called()


def test_unauthorized_creation_blocks_delivery(dependencies):

    dependencies["create_user"].side_effect = UserManagementForbidden()

    with pytest.raises(UserManagementForbidden):
        provision()

    dependencies["issue_invitation"].assert_not_called()
    dependencies["send_invitation_email"].assert_not_called()


def test_token_issuance_failure(dependencies):

    dependencies["issue_invitation"].side_effect = (
        psycopg.OperationalError("Database unavailable")
    )

    result = provision()

    assert result["user"]["status"] == "invited"
    assert result["email_delivery"] == "unconfirmed"
    assert result["invitation_expires_at"] is None
    assert result["audit_recorded"] is False

    dependencies["send_invitation_email"].assert_not_called()


def test_delivery_audit_failure(dependencies):

    dependencies["record_delivery_outcome"].side_effect = (
        psycopg.OperationalError("Database unavailable")
    )

    result = provision()

    assert result["email_delivery"] == "submitted"
    assert result["audit_recorded"] is False

    dependencies["send_invitation_email"].assert_called_once()


def test_invitation_resend(dependencies):

    result = resend()

    assert result["user_id"] == USER_ID
    assert result["email_delivery"] == "submitted"
    assert TOKEN not in str(result)

    dependencies["create_user"].assert_not_called()
    dependencies["issue_invitation"].assert_called_once()
    dependencies["send_invitation_email"].assert_called_once()


def test_unauthorized_resend(dependencies):

    dependencies["issue_invitation"].side_effect = (
        UserManagementForbidden()
    )

    with pytest.raises(UserManagementForbidden):
        resend()

    dependencies["send_invitation_email"].assert_not_called()


def test_resend_delivery_failure(dependencies):

    dependencies["send_invitation_email"].side_effect = (
        EmailDeliveryError("SMTP failure")
    )

    result = resend()

    assert result["email_delivery"] == "unconfirmed"
    assert TOKEN not in str(result)

    dependencies["create_user"].assert_not_called()



from unittest.mock import call

from app.services.auth_rate_limit_service import (
    ProvisioningRateLimitExceeded,
    RateLimitUnavailable,
)


def test_initial_invitation_quota(dependencies):

    result = provision()

    assert result["email_delivery"] == "submitted"

    limiter = dependencies["enforce_provisioning_rate_limit"]

    assert limiter.call_args_list == [
        call(actor_user_id=ADMIN_ID),
        call(
            actor_user_id=ADMIN_ID,
            user_id=USER_ID,
            charge_admin=False,
        ),
    ]


def test_resend_quota(dependencies):

    resend()

    dependencies[
        "enforce_provisioning_rate_limit"
    ].assert_called_once_with(
        actor_user_id=ADMIN_ID,
        user_id=USER_ID,
        charge_admin=True,
    )


@pytest.mark.parametrize("error", [
    ProvisioningRateLimitExceeded(60),
    RateLimitUnavailable(),
])
def test_creation_rate_limit_blocks_side_effects(
    dependencies, error
):

    dependencies[
        "enforce_provisioning_rate_limit"
    ].side_effect = error

    with pytest.raises(type(error)):
        provision()

    dependencies["create_user"].assert_not_called()
    dependencies["issue_invitation"].assert_not_called()
    dependencies["send_invitation_email"].assert_not_called()


@pytest.mark.parametrize("error", [
    ProvisioningRateLimitExceeded(60),
    RateLimitUnavailable(),
])
def test_resend_rate_limit_blocks_side_effects(
    dependencies, error
):

    dependencies[
        "enforce_provisioning_rate_limit"
    ].side_effect = error

    with pytest.raises(type(error)):
        resend()

    dependencies["issue_invitation"].assert_not_called()
    dependencies["send_invitation_email"].assert_not_called()


@pytest.mark.parametrize("error", [
    ProvisioningRateLimitExceeded(60),
    RateLimitUnavailable(),
])
def test_initial_invitation_reservation_failure(
    dependencies, error
):

    dependencies[
        "enforce_provisioning_rate_limit"
    ].side_effect = [None, error]

    result = provision()

    assert result["user"]["status"] == "invited"
    assert result["email_delivery"] == "unconfirmed"
    assert result["invitation_expires_at"] is None

    dependencies["create_user"].assert_called_once()
    dependencies["issue_invitation"].assert_not_called()
    dependencies["send_invitation_email"].assert_not_called()
