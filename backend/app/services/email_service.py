"""Secure transactional email delivery for IntelSOC."""

import os
import re
import ssl
import smtplib

from email.message import EmailMessage
from email.utils import formataddr


class EmailConfigurationError(Exception):
    """SMTP configuration is missing or invalid."""


class EmailDeliveryError(Exception):
    """Email delivery could not be confirmed."""


def validate_email(address):
    if not isinstance(address, str):
        raise ValueError("Invalid email address")

    address = address.strip()

    if len(address) > 254 or not re.fullmatch(
        r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        address,
    ):
        raise ValueError("Invalid email address")

    return address


def get_smtp_config():
    config = {
        "host": os.getenv("INTELSOC_SMTP_HOST", ""),
        "port": os.getenv("INTELSOC_SMTP_PORT", ""),
        "username": os.getenv("INTELSOC_SMTP_USERNAME", ""),
        "password": os.getenv("INTELSOC_SMTP_PASSWORD", ""),
        "sender": os.getenv("INTELSOC_SMTP_FROM", ""),
        "timeout": os.getenv("INTELSOC_SMTP_TIMEOUT", "15"),
    }

    if not all(config.values()):
        raise EmailConfigurationError(
            "SMTP configuration incomplete"
        )

    try:
        config["port"] = int(config["port"])
        config["timeout"] = int(config["timeout"])

        config["username"] = validate_email(config["username"])
        config["sender"] = validate_email(config["sender"])

    except ValueError:
        raise EmailConfigurationError(
            "Invalid SMTP configuration"
        ) from None

    if (
        config["host"] != "smtp.gmail.com"
        or config["port"] != 587
        or not 1 <= config["timeout"] <= 30
        or config["sender"] != config["username"]
        or os.getenv("INTELSOC_SMTP_STARTTLS") != "true"
    ):
        raise EmailConfigurationError(
            "Unsupported or insecure SMTP configuration"
        )

    return config


def send_email(*, recipient, subject, body):
    """Send a plain-text transactional email over verified TLS."""

    recipient = validate_email(recipient)

    if (
        not isinstance(subject, str)
        or not subject.strip()
        or len(subject) > 200
        or "\r" in subject
        or "\n" in subject
    ):
        raise ValueError("Invalid email subject")

    if (
        not isinstance(body, str)
        or not body.strip()
        or len(body) > 20000
    ):
        raise ValueError("Invalid email body")

    config = get_smtp_config()

    message = EmailMessage()

    message["From"] = formataddr(
        ("IntelSOC Security", config["sender"])
    )
    message["To"] = recipient
    message["Subject"] = subject

    message.set_content(body)

    try:
        with smtplib.SMTP(
            config["host"],
            config["port"],
            timeout=config["timeout"],
        ) as smtp:

            smtp.ehlo()

            if not smtp.has_extn("starttls"):
                raise EmailDeliveryError(
                    "Secure SMTP connection unavailable"
                )

            smtp.starttls(
                context=ssl.create_default_context()
            )

            smtp.ehlo()

            smtp.login(
                config["username"],
                config["password"],
            )

            refused = smtp.send_message(
                message,
                from_addr=config["sender"],
                to_addrs=[recipient],
            )

            if refused:
                raise EmailDeliveryError(
                    "Email recipient rejected"
                )

    except (smtplib.SMTPException, OSError):
        raise EmailDeliveryError(
            "Email delivery could not be confirmed"
        ) from None

    return True
