from unittest.mock import Mock

import pytest

from app.services import auth_email_service as service
from app.services.email_service import EmailConfigurationError


TOKEN = "a" * 43
ORIGIN = "https://localhost:8443"


@pytest.fixture(autouse=True)
def configure_origin(monkeypatch):
    monkeypatch.setenv(
        "INTELSOC_DASHBOARD_ORIGIN",
        ORIGIN,
    )


def build_email(**overrides):
    params = {
        "username": "test_user",
        "role": "viewer",
        "invitation_token": TOKEN,
    }

    params.update(overrides)

    return service.build_invitation_email(**params)


@pytest.mark.parametrize("role,label", [
    ("viewer", "Viewer"),
    ("analyst", "Security Analyst"),
    ("administrator", "Administrator"),
])
def test_invitation_content(role, label):
    subject, body = build_email(role=role)

    assert subject == "IntelSOC | Your Account Invitation"
    assert "Hello test_user" in body
    assert f"Assigned role: {label}" in body
    assert "Account status: Invited" in body
    assert "24 hours" in body
    assert "only be used once" in body


def test_secure_activation_link():
    subject, body = build_email()

    assert f"{ORIGIN}/activate#token={TOKEN}" in body
    assert f"?token={TOKEN}" not in body
    assert TOKEN not in subject
    assert body.count(TOKEN) == 1


@pytest.mark.parametrize("origin", [
    "",
    "http://localhost:8443",
    "https://localhost:8443/path",
    "https://localhost:8443?query=test",
    "https://localhost:8443#fragment",
    "https://user:password@localhost:8443",
    "https://localhost:invalid",
    "https://",
    "https://local host:8443",
])
def test_invalid_dashboard_origin(monkeypatch, origin):

    monkeypatch.setenv(
        "INTELSOC_DASHBOARD_ORIGIN",
        origin,
    )

    with pytest.raises(EmailConfigurationError):
        build_email()


@pytest.mark.parametrize("token", [
    "",
    "a" * 42,
    "a" * 44,
    "!" * 43,
    "a" * 42 + "\n",
])
def test_invalid_invitation_token(token):

    with pytest.raises(ValueError):
        build_email(invitation_token=token)


@pytest.mark.parametrize("username", [
    "",
    "ab",
    "a" * 65,
    "user\nInjected content",
])
def test_invalid_username(username):

    with pytest.raises(ValueError):
        build_email(username=username)


def test_invalid_role():

    with pytest.raises(ValueError):
        build_email(role="superadmin")


def test_invitation_email_dispatch(monkeypatch):

    sender = Mock(return_value=True)

    monkeypatch.setattr(service, "send_email", sender)

    result = service.send_invitation_email(
        recipient="test@example.com",
        username="test_user",
        role="analyst",
        invitation_token=TOKEN,
    )

    assert result is True
    sender.assert_called_once()

    params = sender.call_args.kwargs

    assert params["recipient"] == "test@example.com"
    assert params["subject"] == "IntelSOC | Your Account Invitation"
    assert f"{ORIGIN}/activate#token={TOKEN}" in params["body"]
    assert "Security Analyst" in params["body"]


def test_invalid_configuration_blocks_dispatch(monkeypatch):

    sender = Mock()

    monkeypatch.setattr(service, "send_email", sender)

    monkeypatch.setenv(
        "INTELSOC_DASHBOARD_ORIGIN",
        "http://localhost:8443",
    )

    with pytest.raises(EmailConfigurationError):
        service.send_invitation_email(
            recipient="test@example.com",
            username="test_user",
            role="viewer",
            invitation_token=TOKEN,
        )

    sender.assert_not_called()


def test_delivery_failure_propagation(monkeypatch):

    from app.services.email_service import EmailDeliveryError

    sender = Mock(
        side_effect=EmailDeliveryError(
            "Email delivery could not be confirmed"
        )
    )

    monkeypatch.setattr(service, "send_email", sender)

    with pytest.raises(EmailDeliveryError) as error:
        service.send_invitation_email(
            recipient="test@example.com",
            username="test_user",
            role="viewer",
            invitation_token=TOKEN,
        )

    assert TOKEN not in str(error.value)
