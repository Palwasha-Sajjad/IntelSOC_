"""Secure initial Administrator provisioning for IntelSOC."""

import re
from uuid import uuid4

import psycopg

from app.core.config import get_postgres_config
from app.services.auth_security_service import hash_password


class BootstrapError(Exception):
    """Administrator provisioning rejected."""


def normalize_identity(username, email):
    username = username.strip()
    email = email.strip().lower()

    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", username):
        raise ValueError(
            "Username must contain 3-64 valid characters"
        )

    if len(email) > 254 or not re.fullmatch(
        r"[^\s@]+@[^\s@]+\.[^\s@]+", email
    ):
        raise ValueError("Invalid email address")

    return username, email


def bootstrap_admin(*, username, email, password):
    username, email = normalize_identity(username, email)
    password_hash = hash_password(password)

    user_id = uuid4()
    audit_id = uuid4()

    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
    ) as conn:
        with conn.cursor() as cur:

            cur.execute("SET LOCAL lock_timeout = '5s'")

            cur.execute("""
                LOCK TABLE public.users
                IN SHARE ROW EXCLUSIVE MODE
            """)

            cur.execute("""
                SELECT
                    EXISTS (
                        SELECT 1 FROM public.users
                        WHERE role = 'administrator'
                    )
                    OR EXISTS (
                        SELECT 1 FROM public.auth_audit_logs
                        WHERE event_type = 'administrator_bootstrap'
                          AND outcome = 'success'
                    )
            """)

            if cur.fetchone()[0]:
                raise BootstrapError(
                    "Administrator bootstrap has already been completed."
                )

            cur.execute("""
                INSERT INTO public.users (
                    user_id,
                    username,
                    email,
                    password_hash,
                    role,
                    status,
                    password_changed_at
                )
                VALUES (
                    %s, %s, %s, %s,
                    'administrator',
                    'active',
                    NOW()
                )
            """, (
                user_id,
                username,
                email,
                password_hash,
            ))

            cur.execute("""
                INSERT INTO public.auth_audit_logs (
                    audit_id,
                    target_user_id,
                    event_type,
                    outcome,
                    details
                )
                VALUES (
                    %s, %s,
                    'administrator_bootstrap',
                    'success',
                    '{"method": "local_cli"}'::jsonb
                )
            """, (
                audit_id,
                user_id,
            ))

    return {
        "user_id": user_id,
        "username": username,
        "email": email,
        "role": "administrator",
        "status": "active",
    }
