"""Secure invitation-based account activation for IntelSOC."""

import re

from uuid import uuid4

import psycopg
from psycopg.rows import dict_row

from app.core.config import get_postgres_config

from app.services.auth_security_service import (
    validate_password,
    hash_password,
    hash_token,
)

from app.services.auth_session_service import (
    normalize_source_ip,
)


class InvalidInvitation(Exception):
    """Invitation is invalid, expired, revoked or already consumed."""


def activate_account(
    *,
    invitation_token,
    password,
    source_ip=None,
):
    """Activate an invited account using a single-use token."""

    if not isinstance(invitation_token, str) or not re.fullmatch(
        r"[A-Za-z0-9_-]{43}",
        invitation_token,
    ):
        raise InvalidInvitation("Invalid or expired invitation")

    validate_password(password)

    token_digest = hash_token(invitation_token)

    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
        row_factory=dict_row,
    ) as conn:

        with conn.cursor() as cur:

            cur.execute("SET LOCAL lock_timeout = '5s'")

            # Identify the account without locking the token first.

            cur.execute("""
                SELECT user_id
                FROM public.auth_tokens
                WHERE token_hash = %s
                  AND purpose = 'invitation'
                  AND consumed_at IS NULL
                  AND revoked_at IS NULL
                  AND expires_at > clock_timestamp()
            """, (token_digest,))

            candidate = cur.fetchone()

            if candidate is None:
                raise InvalidInvitation(
                    "Invalid or expired invitation"
                )

            user_id = candidate["user_id"]

            # Lock the account before locking its invitation token.
            # This matches the invitation issuance lock order.

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

            if user is None or user["status"] != "invited":
                raise InvalidInvitation(
                    "Invalid or expired invitation"
                )

            # Revalidate after acquiring the account lock.

            cur.execute("""
                SELECT token_id
                FROM public.auth_tokens
                WHERE token_hash = %s
                  AND user_id = %s
                  AND purpose = 'invitation'
                  AND consumed_at IS NULL
                  AND revoked_at IS NULL
                  AND expires_at > clock_timestamp()
                FOR UPDATE
            """, (
                token_digest,
                user_id,
            ))

            invitation = cur.fetchone()

            if invitation is None:
                raise InvalidInvitation(
                    "Invalid or expired invitation"
                )

            password_digest = hash_password(password)

            # Consume the token only if it is still valid.

            cur.execute("""
                UPDATE public.auth_tokens
                SET consumed_at = clock_timestamp()
                WHERE token_id = %s
                  AND consumed_at IS NULL
                  AND revoked_at IS NULL
                  AND expires_at > clock_timestamp()
                RETURNING token_id
            """, (invitation["token_id"],))

            if cur.fetchone() is None:
                raise InvalidInvitation(
                    "Invalid or expired invitation"
                )

            # Activate the account.

            cur.execute("""
                UPDATE public.users
                SET password_hash = %s,
                    status = 'active',
                    password_changed_at = clock_timestamp(),
                    updated_at = clock_timestamp()
                WHERE user_id = %s
                  AND status = 'invited'
                RETURNING
                    user_id,
                    username,
                    email,
                    role,
                    status,
                    password_changed_at
            """, (
                password_digest,
                user_id,
            ))

            activated_user = cur.fetchone()

            if activated_user is None:
                raise InvalidInvitation(
                    "Invalid or expired invitation"
                )

            # Revoke any other outstanding invitation tokens.

            cur.execute("""
                UPDATE public.auth_tokens
                SET revoked_at = clock_timestamp()
                WHERE user_id = %s
                  AND purpose = 'invitation'
                  AND consumed_at IS NULL
                  AND revoked_at IS NULL
            """, (user_id,))

            # Record successful account activation.

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
                    'account_activated',
                    'success',
                    %s
                )
            """, (
                uuid4(),
                user_id,
                user_id,
                normalize_source_ip(source_ip),
            ))

    return activated_user
