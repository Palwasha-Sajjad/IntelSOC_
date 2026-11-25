"""Secure account invitation management for IntelSOC."""

from uuid import uuid4

import psycopg
from psycopg.rows import dict_row

from app.core.config import get_postgres_config

from app.services.auth_security_service import (
    generate_secure_token,
    hash_token,
)

from app.services.auth_session_service import (
    normalize_source_ip,
)

from app.services.user_management_service import (
    require_active_administrator,
)


INVITATION_LIFETIME_SECONDS = 24 * 60 * 60


class InvitationUserNotFound(Exception):
    """Requested account does not exist."""


class InvitationNotAllowed(Exception):
    """Account is not eligible for an invitation."""


def issue_invitation(
    *,
    user_id,
    actor_user_id,
    source_ip=None,
):
    """Issue a new single-use invitation for an invited account."""

    token = generate_secure_token()
    token_digest = hash_token(token)
    token_id = uuid4()

    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
        row_factory=dict_row,
    ) as conn:

        with conn.cursor() as cur:

            cur.execute("SET LOCAL lock_timeout = '5s'")

            require_active_administrator(
                cur,
                actor_user_id,
            )

            cur.execute("""
                SELECT
                    user_id,
                    username,
                    email,
                    role,
                    status
                FROM public.users
                WHERE user_id = %s
                FOR UPDATE
            """, (user_id,))

            user = cur.fetchone()

            if user is None:
                raise InvitationUserNotFound(
                    "User not found"
                )

            if user["status"] != "invited":
                raise InvitationNotAllowed(
                    "Account is not eligible for invitation"
                )

            cur.execute("""
                UPDATE public.auth_tokens
                SET revoked_at = clock_timestamp()
                WHERE user_id = %s
                  AND purpose = 'invitation'
                  AND consumed_at IS NULL
                  AND revoked_at IS NULL
            """, (user_id,))

            cur.execute("""
                INSERT INTO public.auth_tokens (
                    token_id,
                    user_id,
                    token_hash,
                    purpose,
                    created_by,
                    created_at,
                    expires_at
                )
                VALUES (
                    %s,
                    %s,
                    %s,
                    'invitation',
                    %s,
                    clock_timestamp(),
                    clock_timestamp() +
                        (%s * INTERVAL '1 second')
                )
                RETURNING expires_at
            """, (
                token_id,
                user_id,
                token_digest,
                actor_user_id,
                INVITATION_LIFETIME_SECONDS,
            ))

            expires_at = cur.fetchone()["expires_at"]

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
                    %s,
                    %s,
                    %s,
                    'invitation_issued',
                    'success',
                    %s
                )
            """, (
                uuid4(),
                actor_user_id,
                user_id,
                normalize_source_ip(source_ip),
            ))

    return {
        "token_id": token_id,
        "user_id": user["user_id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "invitation_token": token,
        "expires_at": expires_at,
    }
