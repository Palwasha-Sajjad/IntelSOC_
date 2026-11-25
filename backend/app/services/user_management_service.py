"""Administrator-controlled user management for IntelSOC."""

from uuid import uuid4

import psycopg
from psycopg.rows import dict_row

from app.core.config import get_postgres_config
from app.services.auth_bootstrap_service import normalize_identity
from app.services.auth_session_service import normalize_source_ip
from app.services.email_service import validate_email


ALLOWED_ROLES = frozenset({
    "viewer",
    "analyst",
    "administrator",
})

ALLOWED_STATUSES = frozenset({
    "invited",
    "active",
    "suspended",
    "deactivated",
})


class DuplicateUserError(Exception):
    """Username or email already registered."""


class UserManagementForbidden(Exception):
    """Administrative operation not authorized."""


def validate_role(role):
    if role not in ALLOWED_ROLES:
        raise ValueError("Invalid user role")


def require_active_administrator(cur, actor_user_id):
    cur.execute("""
        SELECT user_id
        FROM public.users
        WHERE user_id = %s
          AND role = 'administrator'
          AND status = 'active'
        FOR UPDATE
    """, (actor_user_id,))

    if cur.fetchone() is None:
        raise UserManagementForbidden(
            "Administrator authorization required"
        )


def create_user(
    *,
    username,
    email,
    role,
    actor_user_id,
    source_ip=None,
):
    """Create an invited account without assigning a password."""

    username, email = normalize_identity(username, email)
    email = validate_email(email)
    validate_role(role)

    user_id = uuid4()

    try:
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
                    INSERT INTO public.users (
                        user_id,
                        username,
                        email,
                        role,
                        status,
                        created_by
                    )
                    VALUES (
                        %s, %s, %s, %s,
                        'invited', %s
                    )
                    RETURNING
                        user_id,
                        username,
                        email,
                        role,
                        status,
                        created_by,
                        created_at,
                        updated_at
                """, (
                    user_id,
                    username,
                    email,
                    role,
                    actor_user_id,
                ))

                user = cur.fetchone()

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
                        'user_created',
                        'success',
                        %s
                    )
                """, (
                    uuid4(),
                    actor_user_id,
                    user_id,
                    normalize_source_ip(source_ip),
                ))

        return user

    except psycopg.errors.UniqueViolation:
        raise DuplicateUserError(
            "Username or email already exists"
        ) from None


def list_users(
    *,
    limit=50,
    offset=0,
    role=None,
    status=None,
):
    """Retrieve paginated account metadata without credentials."""

    if not 1 <= limit <= 100:
        raise ValueError("Invalid limit")

    if not 0 <= offset <= 100000:
        raise ValueError("Invalid offset")

    if role is not None:
        validate_role(role)

    if status is not None and status not in ALLOWED_STATUSES:
        raise ValueError("Invalid account status")

    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
        row_factory=dict_row,
    ) as conn:
        with conn.cursor() as cur:

            cur.execute("SET TRANSACTION READ ONLY")

            cur.execute("""
                SELECT
                    user_id,
                    username,
                    email,
                    role,
                    status,
                    created_by,
                    created_at,
                    updated_at,
                    last_login_at,
                    password_changed_at
                FROM public.users
                WHERE (%s::text IS NULL OR role = %s)
                  AND (%s::text IS NULL OR status = %s)
                ORDER BY created_at DESC, user_id DESC
                LIMIT %s OFFSET %s
            """, (
                role, role,
                status, status,
                limit, offset,
            ))

            return list(cur.fetchall())


def get_user(*, user_id):
    """Retrieve one account without exposing credentials."""

    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
        row_factory=dict_row,
    ) as conn:
        with conn.cursor() as cur:

            cur.execute("SET TRANSACTION READ ONLY")

            cur.execute("""
                SELECT
                    user_id,
                    username,
                    email,
                    role,
                    status,
                    created_by,
                    created_at,
                    updated_at,
                    last_login_at,
                    password_changed_at
                FROM public.users
                WHERE user_id = %s
            """, (user_id,))

            return cur.fetchone()
