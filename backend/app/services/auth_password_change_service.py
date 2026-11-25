"""Authenticated password replacement with transactional session revocation."""

import psycopg
from psycopg.rows import dict_row

from app.core.config import get_postgres_config
from app.services.auth_security_service import (
    hash_password, hash_token, validate_password, verify_password,
)
from app.services.auth_session_service import (
    InvalidSession, InvalidCredentials, SESSION_IDLE_SECONDS,
    validate_token_format, record_auth_audit,
)


def change_password(*, user_id, session_token, current_password,
                    new_password, source_ip=None):
    """Recheck the session under the user lock before changing credentials."""
    validate_token_format(session_token)
    validate_password(new_password)
    result = None

    with psycopg.connect(
        **get_postgres_config(), connect_timeout=5, row_factory=dict_row,
    ) as conn:
        with conn.cursor() as cur:
            cur.execute("SET LOCAL lock_timeout = '5s'")
            cur.execute("""
                SELECT user_id, username, email, password_hash, status
                FROM public.users WHERE user_id = %s FOR UPDATE
            """, (user_id,))
            user = cur.fetchone()
            if not user or user["status"] != "active":
                raise InvalidSession()

            cur.execute("""
                SELECT session_id FROM public.auth_sessions
                WHERE user_id = %s AND token_hash = %s
                  AND revoked_at IS NULL
                  AND expires_at > clock_timestamp()
                  AND last_seen_at > clock_timestamp()
                      - (%s * INTERVAL '1 second')
                FOR UPDATE
            """, (user_id, hash_token(session_token), SESSION_IDLE_SECONDS))
            if cur.fetchone() is None:
                raise InvalidSession()

            if not verify_password(current_password, user["password_hash"]):
                record_auth_audit(
                    cur, event_type="password_changed", outcome="failure",
                    user_id=user_id, source_ip=source_ip,
                )
            else:
                if new_password == current_password:
                    raise ValueError("New password must differ from current password")
                new_hash = hash_password(new_password)
                cur.execute("""
                    UPDATE public.users
                    SET password_hash = %s,
                        password_changed_at = clock_timestamp(),
                        updated_at = clock_timestamp()
                    WHERE user_id = %s
                """, (new_hash, user_id))
                cur.execute("""
                    UPDATE public.auth_sessions
                    SET revoked_at = clock_timestamp()
                    WHERE user_id = %s AND revoked_at IS NULL
                """, (user_id,))
                revoked_sessions = cur.rowcount
                cur.execute("""
                    UPDATE public.auth_tokens
                    SET revoked_at = clock_timestamp()
                    WHERE user_id = %s AND purpose = 'password_reset'
                      AND consumed_at IS NULL AND revoked_at IS NULL
                """, (user_id,))
                record_auth_audit(
                    cur, event_type="password_changed", outcome="success",
                    user_id=user_id, source_ip=source_ip,
                )
                result = {
                    "user_id": user_id, "username": user["username"],
                    "email": user["email"], "revoked_sessions": revoked_sessions,
                }

    if result is None:
        raise InvalidCredentials("Incorrect current password")
    return result
