from unittest.mock import patch

import pytest

from app.services import auth_email_service as service

from app.services.email_service import (
    EmailConfigurationError,
    EmailDeliveryError,
)



USERNAME = "viewer_test"
TOKEN = "A" * 43
ORIGIN = "https://localhost:8443"
RECIPIENT = "viewer@example.com"


@pytest.fixture(autouse=True)
def configure_origin(monkeypatch):
    monkeypatch.setenv(
        "INTELSOC_DASHBOARD_ORIGIN",
        ORIGIN,
    )


def test_reset_email_content():

    subject, body = service.build_password_reset_email(
        username=USERNAME,
        reset_token=TOKEN,
    )

    assert subject == "IntelSOC | Password Reset Request"
    assert USERNAME in body
    assert "30 minutes" in body
    assert "used once" in body
    assert "Do not share" in body
    assert "password will remain unchanged" in body


def test_reset_link_uses_secure_fragment():

    _, body = service.build_password_reset_email(
        username=USERNAME,
        reset_token=TOKEN,
    )

    assert (
        f"{ORIGIN}/reset-password#token={TOKEN}"
        in body
    )

    assert "?token=" not in body


@pytest.mark.parametrize("username", [
    "",
    "ab",
    "Ayesha Sajjad",
    "user\nInjected",
    "a" * 65,
    None,
])
def test_invalid_reset_username(username):

    with pytest.raises(ValueError):

        service.build_password_reset_email(
            username=username,
            reset_token=TOKEN,
        )


@pytest.mark.parametrize("token", [
    "",
    "A" * 42,
    "A" * 44,
    "!" * 43,
    " " * 43,
    None,
])
def test_invalid_reset_token(token):

    with pytest.raises(ValueError):

        service.build_password_reset_email(
            username=USERNAME,
            reset_token=token,
        )


@pytest.mark.parametrize("origin", [
    "",
    "http://localhost:8443",
    "https://localhost:8443/untrusted",
    "https://localhost:8443?redirect=example.com",
    "https://localhost:8443#fragment",
    "https://user@localhost:8443",
])
def test_invalid_reset_origin(monkeypatch, origin):

    monkeypatch.setenv(
        "INTELSOC_DASHBOARD_ORIGIN",
        origin,
    )

    with pytest.raises(EmailConfigurationError):

        service.build_password_reset_email(
            username=USERNAME,
            reset_token=TOKEN,
        )


def test_reset_email_delivery():

    with patch.object(
        service,
        "send_email",
        return_value=True,
    ) as sender:

        result = service.send_password_reset_email(
            recipient=RECIPIENT,
            username=USERNAME,
            reset_token=TOKEN,
        )

        assert result is True

        sender.assert_called_once()

        kwargs = sender.call_args.kwargs

        assert kwargs["recipient"] == RECIPIENT
        assert TOKEN in kwargs["body"]
        assert TOKEN not in kwargs["subject"]


def test_password_change_confirmation_content():

    subject, body = (
        service.build_password_change_confirmation_email(
            username=USERNAME,
        )
    )

    assert subject == (
        "IntelSOC | Password Changed Successfully"
    )

    assert USERNAME in body
    assert "sessions have been revoked" in body
    assert "contact your IntelSOC Administrator" in body
    assert "token=" not in body
    assert TOKEN not in body


@pytest.mark.parametrize("username", [
    "",
    "ab",
    "Invalid Username",
    "user\nInjected",
    "a" * 65,
    None,
])
def test_invalid_confirmation_username(username):

    with pytest.raises(ValueError):

        service.build_password_change_confirmation_email(
            username=username,
        )


def test_password_change_confirmation_delivery():

    with patch.object(
        service,
        "send_email",
        return_value=True,
    ) as sender:

        result = (
            service.send_password_change_confirmation_email(
                recipient=RECIPIENT,
                username=USERNAME,
            )
        )

        assert result is True

        sender.assert_called_once()

        kwargs = sender.call_args.kwargs

        assert kwargs["recipient"] == RECIPIENT
        assert "token=" not in kwargs["body"]


def test_reset_email_delivery_failure():

    with patch.object(
        service,
        "send_email",
        side_effect=EmailDeliveryError(
            "Simulated SMTP failure"
        ),
    ):

        with pytest.raises(EmailDeliveryError):

            service.send_password_reset_email(
                recipient=RECIPIENT,
                username=USERNAME,
                reset_token=TOKEN,
            )
