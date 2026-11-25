"""Transactional administrator-controlled account status and role changes."""

import json
from uuid import UUID, uuid4

import psycopg
from psycopg.rows import dict_row

from app.core.config import get_postgres_config
from app.services.auth_session_service import (
    InvalidSession, SESSION_IDLE_SECONDS, validate_token_format, normalize_source_ip,
)
from app.services.auth_security_service import hash_token
from app.services.user_management_service import (
    UserManagementForbidden, validate_role,
)


class LifecycleUserNotFound(Exception):
    """Target account does not exist."""


class LifecycleConflict(Exception):
    """Requested account transition violates account safety policy."""


STATUS_TRANSITIONS = {
    "invited": frozenset({"deactivated"}),
    "active": frozenset({"suspended", "deactivated"}),
    "suspended": frozenset({"active", "deactivated"}),
    "deactivated": frozenset(),
}


def plan_change(user, *, status=None, role=None):
    """Validate transitions without mutating account state."""
    if (status is None) == (role is None):
        raise ValueError("Exactly one status or role change is required")
    if role is not None:
        validate_role(role)
        if user["status"] not in {"active", "suspended"}:
            raise LifecycleConflict("Role change requires an activated account")
        if role == user["role"]:
            raise LifecycleConflict("Account already has requested role")
        return user["status"], role

    if status not in {"active", "suspended", "deactivated"}:
        raise ValueError("Invalid target status")
    if status not in STATUS_TRANSITIONS[user["status"]]:
        raise LifecycleConflict("Account status transition is not allowed")
    return status, user["role"]


def change_user_account(*, user_id, actor_user_id, session_token,
                        status=None, role=None, source_ip=None):
    """Serialize lifecycle writes and recheck actor authorization in the transaction."""
    user_id = UUID(str(user_id))
    actor_user_id = UUID(str(actor_user_id))
    validate_token_format(session_token)

    with psycopg.connect(
        **get_postgres_config(), connect_timeout=5, row_factory=dict_row,
    ) as conn:
        with conn.cursor() as cur:
            cur.execute("SET LOCAL lock_timeout = '5s'")
            # Acquire before any user row locks. Serializes lifecycle operations
            # with one another without blocking unrelated telemetry tables.
            cur.execute("SELECT pg_advisory_xact_lock(18427, 7047)")
            # Lock actor and target in deterministic order.
            cur.execute("""
                SELECT user_id, role, status, password_hash IS NOT NULL AS has_password
                FROM public.users
                WHERE user_id IN (%s, %s)
                ORDER BY user_id FOR UPDATE
            """, (actor_user_id, user_id))
            users = {row["user_id"]: row for row in cur.fetchall()}
            actor = users.get(actor_user_id)
            if not actor or actor["role"] != "administrator" or actor["status"] != "active":
                raise UserManagementForbidden()
            cur.execute("""
                SELECT session_id FROM public.auth_sessions
                WHERE user_id = %s AND token_hash = %s
                  AND revoked_at IS NULL
                  AND expires_at > clock_timestamp()
                  AND last_seen_at > clock_timestamp()
                      - (%s * INTERVAL '1 second')
                FOR UPDATE
            """, (actor_user_id, hash_token(session_token), SESSION_IDLE_SECONDS))
            if cur.fetchone() is None:
                raise InvalidSession()

            # Prevent administrators from accidentally locking themselves out.
            if user_id == actor_user_id:
                raise LifecycleConflict("Administrators cannot modify their own role or status")
            user = users.get(user_id)
            if user is None:
                raise LifecycleUserNotFound()
            next_status, next_role = plan_change(user, status=status, role=role)
            if next_status == "active" and not user["has_password"]:
                raise LifecycleConflict("Account requires activation before reactivation")

            if (user["status"] == "active" and user["role"] == "administrator"
                    and (next_status != "active" or next_role != "administrator")):
                cur.execute("""
                    SELECT COUNT(*) AS count FROM public.users
                    WHERE status = 'active' AND role = 'administrator'
                      AND user_id <> %s
                """, (user_id,))
                if cur.fetchone()["count"] < 1:
                    raise LifecycleConflict("Cannot remove the last active administrator")

            cur.execute("""
                UPDATE public.users
                SET status = %s, role = %s, updated_at = clock_timestamp()
                WHERE user_id = %s
                RETURNING user_id, username, email, role, status,
                          created_by, created_at, updated_at,
                          last_login_at, password_changed_at
            """, (next_status, next_role, user_id))
            updated = cur.fetchone()
            cur.execute("""
                UPDATE public.auth_sessions SET revoked_at = clock_timestamp()
                WHERE user_id = %s AND revoked_at IS NULL
            """, (user_id,))
            revoked_sessions = cur.rowcount
            cur.execute("""
                UPDATE public.auth_tokens SET revoked_at = clock_timestamp()
                WHERE user_id = %s AND consumed_at IS NULL AND revoked_at IS NULL
            """, (user_id,))
            revoked_tokens = cur.rowcount
            event = "user_status_changed" if status is not None else "user_role_changed"
            details = json.dumps({
                "previous_status": user["status"], "new_status": next_status,
                "previous_role": user["role"], "new_role": next_role,
                "revoked_sessions": revoked_sessions, "revoked_tokens": revoked_tokens,
            })
            cur.execute("""
                INSERT INTO public.auth_audit_logs
                    (audit_id, actor_user_id, target_user_id, event_type,
                     outcome, source_ip, details)
                VALUES (%s, %s, %s, %s, 'success', %s, %s::jsonb)
            """, (uuid4(), actor_user_id, user_id, event,
                  normalize_source_ip(source_ip), details))

    return {"user": updated, "revoked_sessions": revoked_sessions,
            "revoked_tokens": revoked_tokens}
