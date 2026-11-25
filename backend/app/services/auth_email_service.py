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

# --------------------------------------------------
# Password recovery email templates
# --------------------------------------------------

def build_password_reset_email(
    *,
    username,
    reset_token,
):
    """Build a secure password recovery email."""

    import re

    if not isinstance(username, str) or not re.fullmatch(
        r"[A-Za-z0-9_.-]{3,64}",
        username,
    ):
        raise ValueError("Invalid username")

    if not isinstance(reset_token, str) or not re.fullmatch(
        r"[A-Za-z0-9_-]{43}",
        reset_token,
    ):
        raise ValueError("Invalid password reset token")

    origin = get_dashboard_origin()

    reset_link = (
        f"{origin}/reset-password#token={reset_token}"
    )

    subject = "IntelSOC | Password Reset Request"

    body = (
        f"Hello {username},\n\n"
        "A password reset has been requested for your "
        "IntelSOC account.\n\n"
        "To securely reset your password, use the following link:\n\n"
        f"{reset_link}\n\n"
        "This link is valid for 30 minutes and can only "
        "be used once.\n\n"
        "If you did not request a password reset, "
        "you can safely ignore this email. Your existing "
        "password will remain unchanged.\n\n"
        "Do not share this link with anyone.\n\n"
        "Regards,\n"
        "IntelSOC Security"
    )

    return subject, body


def send_password_reset_email(
    *,
    recipient,
    username,
    reset_token,
):
    """Deliver password reset instructions."""

    subject, body = build_password_reset_email(
        username=username,
        reset_token=reset_token,
    )

    return send_email(
        recipient=recipient,
        subject=subject,
        body=body,
    )


def build_password_change_confirmation_email(
    *,
    username,
):
    """Notify a user that their password has changed."""

    import re

    if not isinstance(username, str) or not re.fullmatch(
        r"[A-Za-z0-9_.-]{3,64}",
        username,
    ):
        raise ValueError("Invalid username")

    subject = "IntelSOC | Password Changed Successfully"

    body = (
        f"Hello {username},\n\n"
        "Your IntelSOC account password has been "
        "successfully changed.\n\n"
        "Your previous login sessions have been revoked "
        "for security purposes.\n\n"
        "Please sign in again using your new password.\n\n"
        "If you did not authorize this change, contact "
        "your IntelSOC Administrator immediately.\n\n"
        "Regards,\n"
        "IntelSOC Security"
    )

    return subject, body


def send_password_change_confirmation_email(
    *,
    recipient,
    username,
):
    """Deliver a password change security notification."""

    subject, body = build_password_change_confirmation_email(
        username=username,
    )

    return send_email(
        recipient=recipient,
        subject=subject,
        body=body,
    )
