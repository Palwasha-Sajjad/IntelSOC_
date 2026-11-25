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


PASSWORD_RESET_LIFETIME_SECONDS = 1800


class PasswordResetUserNotFound(Exception):
    pass


class PasswordResetNotAllowed(Exception):
    pass


def issue_password_reset_token(
    *,
    email=None,
    user_id=None,
    actor_user_id=None,
    source_ip=None,
):
    """Issue a password reset token for an eligible active account."""

    if actor_user_id is None:

        if email is None or user_id is not None:
            raise ValueError("Invalid recovery request")

    else:

        if user_id is None or email is not None:
            raise ValueError("Invalid administrator reset request")

    raw_token = generate_secure_token()
    token_hash = hash_token(raw_token)
    token_id = uuid4()

    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
        row_factory=dict_row,
    ) as conn:

        with conn.cursor() as cur:

            cur.execute("SET LOCAL lock_timeout = '5s'")

            if actor_user_id is not None:

                require_active_administrator(
                    cur,
                    actor_user_id,
                )

                cur.execute(
                    '''
                    SELECT user_id, username, email, role, status
                    FROM public.users
                    WHERE user_id = %s
                    FOR UPDATE
                    ''',
                    (user_id,),
                )

            else:

                cur.execute(
                    '''
                    SELECT user_id, username, email, role, status
                    FROM public.users
                    WHERE LOWER(TRIM(email)) = %s
                    FOR UPDATE
                    ''',
                    (email.strip().lower(),),
                )

            user = cur.fetchone()

            if user is None:
                raise PasswordResetUserNotFound(
                    "Account not found"
                )

            if user["status"] != "active":
                raise PasswordResetNotAllowed(
                    "Account is not eligible for password recovery"
                )

            target_user_id = user["user_id"]

            cur.execute(
                '''
                UPDATE public.auth_tokens
                SET revoked_at = clock_timestamp()
                WHERE user_id = %s
                  AND purpose = 'password_reset'
                  AND consumed_at IS NULL
                  AND revoked_at IS NULL
                ''',
                (target_user_id,),
            )

            cur.execute(
                '''
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
                    'password_reset',
                    %s,
                    clock_timestamp(),
                    clock_timestamp()
                        + (%s * INTERVAL '1 second')
                )
                RETURNING expires_at
                ''',
                (
                    token_id,
                    target_user_id,
                    token_hash,
                    actor_user_id,
                    PASSWORD_RESET_LIFETIME_SECONDS,
                ),
            )

            expires_at = cur.fetchone()["expires_at"]

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
                    'password_reset_issued',
                    'success',
                    %s
                )
                ''',
                (
                    uuid4(),
                    actor_user_id,
                    target_user_id,
                    normalize_source_ip(source_ip),
                ),
            )

            result = {
                "token_id": token_id,
                "user_id": target_user_id,
                "username": user["username"],
                "email": user["email"],
                "role": user["role"],
                "reset_token": raw_token,
                "expires_at": expires_at,
            }

    return result
