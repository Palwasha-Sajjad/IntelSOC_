"""User authentication and server-side sessions for IntelSOC."""

from uuid import uuid4
from threading import BoundedSemaphore
import ipaddress
import secrets

import psycopg
from psycopg.rows import dict_row

from app.core.config import get_postgres_config

from app.services.auth_security_service import (
    hash_password,
    verify_password,
    generate_secure_token,
    hash_token,
    password_needs_rehash,
)

from app.services.auth_rate_limit_service import (
    enforce_login_rate_limit,
)


SESSION_LIFETIME_SECONDS = 8 * 60 * 60
SESSION_IDLE_SECONDS = 30 * 60

DUMMY_PASSWORD_HASH = hash_password(
    secrets.token_urlsafe(32)
)

PASSWORD_VERIFICATION_SLOTS = BoundedSemaphore(2)


class InvalidCredentials(Exception):
    """Authentication credentials rejected."""


class AuthenticationBusy(Exception):
    """Authentication processing capacity reached."""


def normalize_source_ip(source_ip):
    try:
        return str(ipaddress.ip_address(source_ip))
    except (ValueError, TypeError):
        return None


def record_auth_audit(
    cur,
    *,
    event_type,
    outcome,
    user_id=None,
    source_ip=None,
):
    cur.execute("""
        INSERT INTO public.auth_audit_logs (
            audit_id,
            actor_user_id,
            target_user_id,
            event_type,
            outcome,
            source_ip
        )
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (
        uuid4(),
        user_id if outcome == "success" else None,
        user_id,
        event_type,
        outcome,
        normalize_source_ip(source_ip),
    ))


def authenticate_user(*, email, password, source_ip=None):

    email = email.strip().lower()
    source_ip = normalize_source_ip(source_ip)

    enforce_login_rate_limit(
        email=email,
        source_ip=source_ip,
    )

    if not PASSWORD_VERIFICATION_SLOTS.acquire(
        blocking=False
    ):
        raise AuthenticationBusy(
            "Authentication temporarily busy"
        )

    result = None

    try:
        with psycopg.connect(
            **get_postgres_config(),
            connect_timeout=5,
            row_factory=dict_row,
        ) as conn:
            with conn.cursor() as cur:

                cur.execute("""
                    SET LOCAL lock_timeout = '5s'
                """)

                cur.execute("""
                    SELECT
                        user_id,
                        username,
                        email,
                        password_hash,
                        role,
                        status
                    FROM public.users
                    WHERE LOWER(TRIM(email)) = %s
                    FOR UPDATE
                """, (email,))

                user = cur.fetchone()

                usable_hash = (
                    user["password_hash"]
                    if user and user["password_hash"]
                    else DUMMY_PASSWORD_HASH
                )

                password_valid = verify_password(
                    password,
                    usable_hash,
                )

                if (
                    user is None
                    or user["status"] != "active"
                    or not user["password_hash"]
                    or not password_valid
                ):
                    record_auth_audit(
                        cur,
                        event_type="login",
                        outcome="failure",
                        user_id=(
                            user["user_id"] if user else None
                        ),
                        source_ip=source_ip,
                    )

                else:
                    if password_needs_rehash(
                        user["password_hash"]
                    ):
                        updated_hash = hash_password(password)

                        cur.execute("""
                            UPDATE public.users
                            SET password_hash = %s,
                                updated_at = NOW()
                            WHERE user_id = %s
                        """, (
                            updated_hash,
                            user["user_id"],
                        ))

                    session_id = uuid4()
                    token = generate_secure_token()

                    cur.execute("""
                        INSERT INTO public.auth_sessions (
                            session_id,
                            user_id,
                            token_hash,
                            expires_at
                        )
                        VALUES (
                            %s, %s, %s,
                            NOW() + (
                                %s * INTERVAL '1 second'
                            )
                        )
                        RETURNING expires_at
                    """, (
                        session_id,
                        user["user_id"],
                        hash_token(token),
                        SESSION_LIFETIME_SECONDS,
                    ))

                    expires_at = cur.fetchone()["expires_at"]

                    cur.execute("""
                        UPDATE public.users
                        SET last_login_at = NOW()
                        WHERE user_id = %s
                    """, (user["user_id"],))

                    record_auth_audit(
                        cur,
                        event_type="login",
                        outcome="success",
                        user_id=user["user_id"],
                        source_ip=source_ip,
                    )

                    result = {
                        "session_id": session_id,
                        "session_token": token,
                        "expires_at": expires_at,
                        "user": {
                            "user_id": user["user_id"],
                            "username": user["username"],
                            "email": user["email"],
                            "role": user["role"],
                            "status": user["status"],
                        },
                    }

    finally:
        PASSWORD_VERIFICATION_SLOTS.release()

    if result is None:
        raise InvalidCredentials(
            "Invalid email or password"
        )

    return result

class InvalidSession(Exception):
    """Missing, expired, revoked or otherwise invalid session."""


def validate_token_format(token):
    """Reject malformed session tokens before database access."""

    if not isinstance(token, str):
        raise InvalidSession("Invalid or expired session")

    if len(token) != 43:
        raise InvalidSession("Invalid or expired session")

    if not all(
        char in (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789-_"
        )
        for char in token
    ):
        raise InvalidSession("Invalid or expired session")


def validate_session(token):
    """Validate a session and retrieve current account permissions."""

    validate_token_format(token)

    result = None

    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
        row_factory=dict_row,
    ) as conn:
        with conn.cursor() as cur:

            cur.execute("SET LOCAL lock_timeout = '5s'")

            cur.execute("""
                UPDATE public.auth_sessions AS s
                SET last_seen_at = clock_timestamp()
                FROM public.users AS u
                WHERE s.user_id = u.user_id
                  AND s.token_hash = %s
                  AND s.revoked_at IS NULL
                  AND s.expires_at > clock_timestamp()
                  AND s.last_seen_at >
                      clock_timestamp() -
                      (%s * INTERVAL '1 second')
                  AND u.status = 'active'
                RETURNING
                    s.session_id,
                    s.expires_at,
                    s.last_seen_at,
                    u.user_id,
                    u.username,
                    u.email,
                    u.role,
                    u.status
            """, (
                hash_token(token),
                SESSION_IDLE_SECONDS,
            ))

            result = cur.fetchone()

    if result is None:
        raise InvalidSession("Invalid or expired session")

    return result


def revoke_session(token, source_ip=None):
    """Revoke a session and record successful logout."""

    validate_token_format(token)

    revoked = False

    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
        row_factory=dict_row,
    ) as conn:
        with conn.cursor() as cur:

            cur.execute("SET LOCAL lock_timeout = '5s'")

            cur.execute("""
                UPDATE public.auth_sessions
                SET revoked_at = clock_timestamp()
                WHERE token_hash = %s
                  AND revoked_at IS NULL
                RETURNING user_id
            """, (hash_token(token),))

            session = cur.fetchone()

            if session is not None:
                record_auth_audit(
                    cur,
                    event_type="logout",
                    outcome="success",
                    user_id=session["user_id"],
                    source_ip=source_ip,
                )

                revoked = True

    return revoked
