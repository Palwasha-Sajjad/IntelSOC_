from uuid import uuid4

import psycopg

from app.core.config import get_postgres_config

from app.services.auth_session_service import (
    normalize_source_ip,
)

from app.services.auth_rate_limit_service import (
    enforce_password_recovery_rate_limit,
)

from app.services.auth_password_reset_token_service import (
    issue_password_reset_token,
    PasswordResetUserNotFound,
    PasswordResetNotAllowed,
)

from app.services.auth_email_service import (
    get_dashboard_origin,
    send_password_reset_email,
)

from app.services.email_service import (
    get_smtp_config,
    validate_email,
    EmailConfigurationError,
    EmailDeliveryError,
)


GENERIC_RECOVERY_MESSAGE = (
    "If an eligible account exists for this email address, "
    "password reset instructions will be sent."
)


def record_recovery_email_outcome(
    *,
    user_id,
    outcome,
    actor_user_id=None,
    source_ip=None,
):
    """Record email delivery outcome without storing secrets."""

    if outcome not in {"success", "failure"}:
        raise ValueError("Invalid audit outcome")

    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
    ) as conn:

        with conn.cursor() as cur:

            cur.execute("SET LOCAL lock_timeout = '5s'")

            cur.execute(
                '''
                INSERT INTO public.auth_audit_logs (
                    audit_id,
                    actor_user_id,
                    target_user_id,
                    event_type,
                    outcome,
                    source_ip
                )
                VALUES (
                    %s,
                    %s,
                    %s,
                    'password_reset_email',
                    %s,
                    %s
                )
                ''',
                (
                    uuid4(),
                    actor_user_id,
                    user_id,
                    outcome,
                    normalize_source_ip(source_ip),
                ),
            )


def deliver_password_reset(
    *,
    issued_token,
    actor_user_id=None,
    source_ip=None,
):
    """Deliver an already committed password reset token."""

    submitted = False

    try:

        submitted = send_password_reset_email(
            recipient=issued_token["email"],
            username=issued_token["username"],
            reset_token=issued_token["reset_token"],
        ) is True

    except (
        EmailConfigurationError,
        EmailDeliveryError,
        ValueError,
        OSError,
    ):

        submitted = False

    audit_recorded = True

    try:

        record_recovery_email_outcome(
            user_id=issued_token["user_id"],
            actor_user_id=actor_user_id,
            source_ip=source_ip,
            outcome="success" if submitted else "failure",
        )

    except (
        psycopg.Error,
        OSError,
        KeyError,
    ):

        audit_recorded = False

    return {
        "user_id": issued_token["user_id"],
        "reset_expires_at": issued_token["expires_at"],
        "email_delivery": (
            "submitted" if submitted else "unconfirmed"
        ),
        "audit_recorded": audit_recorded,
    }


def request_password_recovery(
    *,
    email,
    source_ip=None,
):
    """Process self-service recovery without exposing account state."""

    normalized_email = validate_email(email).lower()

    enforce_password_recovery_rate_limit(
        email=normalized_email,
        source_ip=source_ip,
    )

    get_dashboard_origin()
    get_smtp_config()

    try:

        issued = issue_password_reset_token(
            email=normalized_email,
            source_ip=source_ip,
        )

    except (
        PasswordResetUserNotFound,
        PasswordResetNotAllowed,
    ):

        return {
            "message": GENERIC_RECOVERY_MESSAGE,
        }

    deliver_password_reset(
        issued_token=issued,
        source_ip=source_ip,
    )

    return {
        "message": GENERIC_RECOVERY_MESSAGE,
    }

# --------------------------------------------------
# Administrator-initiated password recovery
# --------------------------------------------------

from app.services.auth_rate_limit_service import (
    enforce_provisioning_rate_limit,
)

from app.services.user_management_service import (
    get_user,
)


def request_administrator_password_reset(
    *,
    user_id,
    actor_user_id,
    source_ip=None,
):
    """Initiate recovery without exposing the user's reset token."""

    get_dashboard_origin()
    get_smtp_config()

    enforce_provisioning_rate_limit(
        actor_user_id=actor_user_id,
        user_id=user_id,
    )

    target = get_user(user_id=user_id)

    if target is None:

        raise PasswordResetUserNotFound(
            "Account not found"
        )

    if target["status"] != "active":

        raise PasswordResetNotAllowed(
            "Account is not eligible for password recovery"
        )

    # Share the recipient recovery quota with self-service
    # requests to prevent bypassing email cooldown limits.

    enforce_password_recovery_rate_limit(
        email=target["email"],
        source_ip=source_ip,
    )

    # The token service rechecks administrator authorization
    # and target account eligibility inside the transaction.

    issued = issue_password_reset_token(
        user_id=user_id,
        actor_user_id=actor_user_id,
        source_ip=source_ip,
    )

    return deliver_password_reset(
        issued_token=issued,
        actor_user_id=actor_user_id,
        source_ip=source_ip,
    )
