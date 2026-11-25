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


class InvalidPasswordResetToken(Exception):
    pass


def reset_password(
    *,
    reset_token,
    password,
    source_ip=None,
):
    """Consume a valid reset token and securely replace a password."""

    if not isinstance(reset_token, str) or not re.fullmatch(
        r"[A-Za-z0-9_-]{43}",
        reset_token,
    ):
        raise InvalidPasswordResetToken(
            "Invalid or expired password reset token"
        )

    validate_password(password)

    token_hash = hash_token(reset_token)

    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
        row_factory=dict_row,
    ) as conn:

        with conn.cursor() as cur:

            cur.execute("SET LOCAL lock_timeout = '5s'")

            # Locate the account associated with a valid token.

            cur.execute(
                '''
                SELECT user_id
                FROM public.auth_tokens
                WHERE token_hash = %s
                  AND purpose = 'password_reset'
                  AND consumed_at IS NULL
                  AND revoked_at IS NULL
                  AND expires_at > clock_timestamp()
                ''',
                (token_hash,),
            )

            token = cur.fetchone()

            if token is None:
                raise InvalidPasswordResetToken(
                    "Invalid or expired password reset token"
                )

            user_id = token["user_id"]

            # Lock the account before locking its reset token.

            cur.execute(
                '''
                SELECT user_id, username, email, role, status
                FROM public.users
                WHERE user_id = %s
                FOR UPDATE
                ''',
                (user_id,),
            )

            user = cur.fetchone()

            if user is None or user["status"] != "active":
                raise InvalidPasswordResetToken(
                    "Invalid or expired password reset token"
                )

            # Revalidate the token after obtaining the user lock.

            cur.execute(
                '''
                SELECT token_id
                FROM public.auth_tokens
                WHERE user_id = %s
                  AND token_hash = %s
                  AND purpose = 'password_reset'
                  AND consumed_at IS NULL
                  AND revoked_at IS NULL
                  AND expires_at > clock_timestamp()
                FOR UPDATE
                ''',
                (user_id, token_hash),
            )

            locked_token = cur.fetchone()

            if locked_token is None:
                raise InvalidPasswordResetToken(
                    "Invalid or expired password reset token"
                )

            password_hash = hash_password(password)

            # Consume the token exactly once.

            cur.execute(
                '''
                UPDATE public.auth_tokens
                SET consumed_at = clock_timestamp()
                WHERE token_id = %s
                  AND purpose = 'password_reset'
                  AND consumed_at IS NULL
                  AND revoked_at IS NULL
                  AND expires_at > clock_timestamp()
                RETURNING token_id
                ''',
                (locked_token["token_id"],),
            )

            if cur.fetchone() is None:
                raise InvalidPasswordResetToken(
                    "Invalid or expired password reset token"
                )

            # Replace the account password.

            cur.execute(
                '''
                UPDATE public.users
                SET password_hash = %s,
                    password_changed_at = clock_timestamp(),
                    updated_at = clock_timestamp()
                WHERE user_id = %s
                  AND status = 'active'
                RETURNING password_changed_at
                ''',
                (password_hash, user_id),
            )

            updated = cur.fetchone()

            if updated is None:
                raise InvalidPasswordResetToken(
                    "Invalid or expired password reset token"
                )

            # Revoke every existing session for the account.

            cur.execute(
                '''
                UPDATE public.auth_sessions
                SET revoked_at = clock_timestamp()
                WHERE user_id = %s
                  AND revoked_at IS NULL
                ''',
                (user_id,),
            )

            revoked_sessions = cur.rowcount

            # Invalidate remaining password reset tokens.

            cur.execute(
                '''
                UPDATE public.auth_tokens
                SET revoked_at = clock_timestamp()
                WHERE user_id = %s
                  AND purpose = 'password_reset'
                  AND consumed_at IS NULL
                  AND revoked_at IS NULL
                ''',
                (user_id,),
            )

            # Audit the completed password reset.

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
                    'password_reset_completed',
                    'success',
                    %s
                )
                ''',
                (
                    uuid4(),
                    user_id,
                    user_id,
                    normalize_source_ip(source_ip),
                ),
            )

            result = {
                "user_id": user_id,
                "username": user["username"],
                "email": user["email"],
                "role": user["role"],
                "password_changed_at": (
                    updated["password_changed_at"]
                ),
                "revoked_sessions": revoked_sessions,
            }

    return result
