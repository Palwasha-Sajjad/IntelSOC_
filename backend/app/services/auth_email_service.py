"""Account-related transactional emails for IntelSOC."""

import os
import re

from urllib.parse import urlsplit

from app.services.email_service import (
    send_email,
    EmailConfigurationError,
)


ROLE_LABELS = {
    "viewer": "Viewer",
    "analyst": "Security Analyst",
    "administrator": "Administrator",
}


def get_dashboard_origin():
    origin = os.getenv(
        "INTELSOC_DASHBOARD_ORIGIN", ""
    ).strip()

    try:
        parsed = urlsplit(origin)
        port = parsed.port

        valid = (
            parsed.scheme == "https"
            and parsed.hostname
            and not parsed.username
            and not parsed.password
            and not parsed.path
            and not parsed.query
            and not parsed.fragment
            and origin == f"https://{parsed.netloc}"
            and not any(char.isspace() for char in origin)
            and "\\" not in origin
        )

    except ValueError:
        valid = False

    if not valid:
        raise EmailConfigurationError(
            "Invalid dashboard origin"
        )

    return origin


def build_invitation_email(
    *,
    username,
    role,
    invitation_token,
):
    """Build an invitation without logging its raw token."""

    if role not in ROLE_LABELS:
        raise ValueError("Invalid user role")

    if not isinstance(username, str) or not re.fullmatch(
        r"[A-Za-z0-9_.-]{3,64}", username
    ):
        raise ValueError("Invalid username")

    if not isinstance(invitation_token, str) or not re.fullmatch(
        r"[A-Za-z0-9_-]{43}", invitation_token
    ):
        raise ValueError("Invalid invitation token")

    origin = get_dashboard_origin()

    activation_url = (
        f"{origin}/activate"
        f"#token={invitation_token}"
    )

    subject = "IntelSOC | Your Account Invitation"

    body = f"""Hello {username},

You have been invited to join IntelSOC - Smart Threat Intelligence and Response System.

Your account details:

Username: {username}
Assigned role: {ROLE_LABELS[role]}
Account status: Invited

Activate your account and create your password using the following secure link:

{activation_url}

This invitation is valid for 24 hours and can only be used once.

Do not share this invitation link with anyone.

If your invitation expires, contact your IntelSOC Administrator.

If you were not expecting this invitation, please ignore this email.

Regards,
IntelSOC Security Team
Smart Threat Intelligence and Response System
"""

    return subject, body


def send_invitation_email(
    *,
    recipient,
    username,
    role,
    invitation_token,
):
    """Submit an account invitation through secure SMTP."""

    subject, body = build_invitation_email(
        username=username,
        role=role,
        invitation_token=invitation_token,
    )

    return send_email(
        recipient=recipient,
        subject=subject,
        body=body,
    )
