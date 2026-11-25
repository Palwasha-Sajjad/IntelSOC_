"""Centralized role-based access control for IntelSOC."""

import psycopg

from fastapi import Depends, HTTPException, Request, Response

from app.api.routes.auth import (
    SESSION_COOKIE,
    require_trusted_origin,
)

from app.services.auth_session_service import (
    validate_session,
    InvalidSession,
)


VIEWER_ROLES = frozenset({
    "viewer",
    "analyst",
    "administrator",
})

ANALYST_ROLES = frozenset({
    "analyst",
    "administrator",
})

ADMINISTRATOR_ROLES = frozenset({
    "administrator",
})


def get_authenticated_user(
    request: Request,
    response: Response,
):
    """Authenticate a user through the server-side session."""

    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        require_trusted_origin(request)

    token = request.cookies.get(SESSION_COOKIE)

    try:
        user = validate_session(token)

    except InvalidSession:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired session",
            headers={"Cache-Control": "no-store"},
        ) from None

    except (psycopg.Error, OSError, KeyError):
        raise HTTPException(
            status_code=503,
            detail="Authentication temporarily unavailable",
            headers={"Cache-Control": "no-store"},
        ) from None

    if user.get("status") != "active":
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired session",
            headers={"Cache-Control": "no-store"},
        )

    response.headers["Cache-Control"] = "no-store"

    return user


def require_role(user, allowed_roles):
    """Reject users without the required permission."""

    if user.get("role") not in allowed_roles:
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions",
            headers={"Cache-Control": "no-store"},
        )

    return user


def require_viewer(
    user: dict = Depends(get_authenticated_user),
):
    return require_role(user, VIEWER_ROLES)


def require_analyst(
    user: dict = Depends(get_authenticated_user),
):
    return require_role(user, ANALYST_ROLES)


def require_administrator(
    user: dict = Depends(get_authenticated_user),
):
    return require_role(user, ADMINISTRATOR_ROLES)
