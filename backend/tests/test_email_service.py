from unittest.mock import MagicMock

import smtplib
import pytest

from app.services import email_service


@pytest.fixture(autouse=True)
def smtp_config(monkeypatch):
    settings = {
        "INTELSOC_SMTP_HOST": "smtp.gmail.com",
        "INTELSOC_SMTP_PORT": "587",
        "INTELSOC_SMTP_USERNAME": "intelsoc@example.com",
        "INTELSOC_SMTP_PASSWORD": "test-app-password",
        "INTELSOC_SMTP_FROM": "intelsoc@example.com",
        "INTELSOC_SMTP_STARTTLS": "true",
        "INTELSOC_SMTP_TIMEOUT": "15",
    }

    for key, value in settings.items():
        monkeypatch.setenv(key, value)


@pytest.fixture
def smtp(monkeypatch):
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.has_extn.return_value = True
    connection.send_message.return_value = {}

    factory = MagicMock(return_value=connection)

    monkeypatch.setattr(
        email_service.smtplib,
        "SMTP",
        factory,
    )

    return connection


def send_test_email():
    return email_service.send_email(
        recipient="user@example.com",
        subject="IntelSOC Test",
        body="Secure email delivery test.",
    )


def test_valid_configuration():
    config = email_service.get_smtp_config()

    assert config["host"] == "smtp.gmail.com"
    assert config["port"] == 587
    assert config["timeout"] == 15


@pytest.mark.parametrize("key", [
    "INTELSOC_SMTP_HOST",
    "INTELSOC_SMTP_PORT",
    "INTELSOC_SMTP_USERNAME",
    "INTELSOC_SMTP_PASSWORD",
    "INTELSOC_SMTP_FROM",
])
def test_missing_configuration(monkeypatch, key):
    monkeypatch.delenv(key, raising=False)

    with pytest.raises(email_service.EmailConfigurationError):
        email_service.get_smtp_config()


@pytest.mark.parametrize("key,value", [
    ("INTELSOC_SMTP_HOST", "untrusted.example.com"),
    ("INTELSOC_SMTP_PORT", "25"),
    ("INTELSOC_SMTP_STARTTLS", "false"),
    ("INTELSOC_SMTP_TIMEOUT", "0"),
    ("INTELSOC_SMTP_TIMEOUT", "60"),
    ("INTELSOC_SMTP_FROM", "other@example.com"),
])
def test_insecure_configuration(monkeypatch, key, value):
    monkeypatch.setenv(key, value)

    with pytest.raises(email_service.EmailConfigurationError):
        email_service.get_smtp_config()


def test_successful_email_delivery(smtp):
    assert send_test_email() is True

    smtp.starttls.assert_called_once()
    smtp.login.assert_called_once()
    smtp.send_message.assert_called_once()

    operations = [call[0] for call in smtp.method_calls]

    assert operations.index("starttls") < operations.index("login")
    assert operations.index("login") < operations.index("send_message")

    context = smtp.starttls.call_args.kwargs["context"]

    assert context.check_hostname is True
    assert context.verify_mode == email_service.ssl.CERT_REQUIRED

    message = smtp.send_message.call_args.args[0]

    assert message["To"] == "user@example.com"
    assert message["Subject"] == "IntelSOC Test"
    assert "test-app-password" not in message.as_string()


def test_missing_starttls_blocks_delivery(smtp):
    smtp.has_extn.return_value = False

    with pytest.raises(email_service.EmailDeliveryError):
        send_test_email()

    smtp.login.assert_not_called()
    smtp.send_message.assert_not_called()


def test_authentication_failure_sanitized(smtp):
    smtp.login.side_effect = smtplib.SMTPAuthenticationError(
        535,
        b"sensitive-provider-error",
    )

    with pytest.raises(email_service.EmailDeliveryError) as error:
        send_test_email()

    assert "sensitive-provider-error" not in str(error.value)
    smtp.send_message.assert_not_called()


def test_connection_failure_sanitized(monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("sensitive-connection-information")

    monkeypatch.setattr(email_service.smtplib, "SMTP", fail)

    with pytest.raises(email_service.EmailDeliveryError) as error:
        send_test_email()

    assert "sensitive-connection-information" not in str(error.value)


def test_recipient_refusal(smtp):
    smtp.send_message.return_value = {
        "user@example.com": (550, b"Rejected")
    }

    with pytest.raises(email_service.EmailDeliveryError):
        send_test_email()


@pytest.mark.parametrize("recipient", [
    "",
    "invalid-email",
    "user@example.com\r\nBcc: other@example.com",
    "user@example.com,other@example.com",
])
def test_invalid_recipient(smtp, recipient):
    with pytest.raises(ValueError):
        email_service.send_email(
            recipient=recipient,
            subject="Test",
            body="Test message",
        )

    smtp.login.assert_not_called()
    smtp.send_message.assert_not_called()


@pytest.mark.parametrize("subject", [
    "",
    "Test\r\nBcc: other@example.com",
    "a" * 201,
])
def test_invalid_subject(smtp, subject):
    with pytest.raises(ValueError):
        email_service.send_email(
            recipient="user@example.com",
            subject=subject,
            body="Test message",
        )

    smtp.send_message.assert_not_called()


@pytest.mark.parametrize("body", [
    "",
    "   ",
    "a" * 20001,
])
def test_invalid_body(smtp, body):
    with pytest.raises(ValueError):
        email_service.send_email(
            recipient="user@example.com",
            subject="Test",
            body=body,
        )

    smtp.send_message.assert_not_called()
