"""Account provisioning and automatic invitation delivery."""

from uuid import uuid4

import psycopg

from app.core.config import get_postgres_config

from app.services.user_management_service import create_user

from app.services.auth_invitation_service import (
    issue_invitation,
    InvitationUserNotFound,
    InvitationNotAllowed,
)

from app.services.auth_rate_limit_service import (
    enforce_provisioning_rate_limit,
    ProvisioningRateLimitExceeded,
    RateLimitUnavailable,
)

from app.services.user_management_service import (
    UserManagementForbidden,
)

from app.services.auth_email_service import (
    send_invitation_email,
    get_dashboard_origin,
)

from app.services.auth_session_service import normalize_source_ip

from app.services.email_service import (
    get_smtp_config,
    EmailConfigurationError,
    EmailDeliveryError,
)


def record_delivery_outcome(
    *,
    user_id,
    actor_user_id,
    outcome,
    source_ip=None,
):
    """Record SMTP submission outcome without storing secrets."""

    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
    ) as conn:

        with conn.cursor() as cur:

            cur.execute("""
                INSERT INTO public.auth_audit_logs (
                    audit_id,
                    actor_user_id,
                    target_user_id,
                    event_type,
                    outcome,
                    source_ip
                )
                VALUES (
                    %s, %s, %s,
                    'invitation_email',
                    %s, %s
                )
            """, (
                uuid4(),
                actor_user_id,
                user_id,
                outcome,
                normalize_source_ip(source_ip),
            ))


def deliver_invitation(
    *,
    user_id,
    actor_user_id,
    source_ip=None,
    _admin_quota_reserved=False,
):
    """Issue a fresh invitation and submit it through SMTP."""

    get_dashboard_origin()
    get_smtp_config()

    enforce_provisioning_rate_limit(
        actor_user_id=actor_user_id,
        user_id=user_id,
        charge_admin=not _admin_quota_reserved,
    )

    invitation = issue_invitation(
        user_id=user_id,
        actor_user_id=actor_user_id,
        source_ip=source_ip,
    )

    try:
        submitted = send_invitation_email(
            recipient=invitation["email"],
            username=invitation["username"],
            role=invitation["role"],
            invitation_token=invitation["invitation_token"],
        )

        delivery_status = (
            "submitted" if submitted
            else "unconfirmed"
        )

    except (
        EmailConfigurationError,
        EmailDeliveryError,
        ValueError,
    ):
        delivery_status = "unconfirmed"

    audit_recorded = True

    try:
        record_delivery_outcome(
            user_id=user_id,
            actor_user_id=actor_user_id,
            outcome=(
                "success"
                if delivery_status == "submitted"
                else "failure"
            ),
            source_ip=source_ip,
        )

    except (psycopg.Error, OSError, KeyError):
        audit_recorded = False

    return {
        "user_id": user_id,
        "invitation_expires_at": invitation["expires_at"],
        "email_delivery": delivery_status,
        "audit_recorded": audit_recorded,
    }


def provision_user(
    *,
    username,
    email,
    role,
    actor_user_id,
    source_ip=None,
):
    """Create an invited account and send its invitation."""

    get_dashboard_origin()
    get_smtp_config()

    enforce_provisioning_rate_limit(
        actor_user_id=actor_user_id,
    )

    user = create_user(
        username=username,
        email=email,
        role=role,
        actor_user_id=actor_user_id,
        source_ip=source_ip,
    )

    try:
        delivery = deliver_invitation(
            user_id=user["user_id"],
            actor_user_id=actor_user_id,
            source_ip=source_ip,
            _admin_quota_reserved=True,
        )

    except (
        psycopg.Error,
        OSError,
        KeyError,
        EmailConfigurationError,
        ProvisioningRateLimitExceeded,
        RateLimitUnavailable,
        UserManagementForbidden,
        InvitationUserNotFound,
        InvitationNotAllowed,
    ):
        delivery = {
            "user_id": user["user_id"],
            "invitation_expires_at": None,
            "email_delivery": "unconfirmed",
            "audit_recorded": False,
        }

    return {
        "user": user,
        "invitation_expires_at": delivery[
            "invitation_expires_at"
        ],
        "email_delivery": delivery["email_delivery"],
        "audit_recorded": delivery["audit_recorded"],
    }
