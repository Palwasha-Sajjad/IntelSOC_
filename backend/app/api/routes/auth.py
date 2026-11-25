"""Secure user authentication endpoints for IntelSOC."""

import os
from urllib.parse import urlsplit

import psycopg

from fastapi import (
    APIRouter,
    HTTPException,
    Request,
    Response,
)
from pydantic import BaseModel, Field

from app.services.auth_session_service import (
    authenticate_user,
    validate_session,
    revoke_session,
    InvalidCredentials,
    InvalidSession,
    AuthenticationBusy,
    SESSION_LIFETIME_SECONDS,
)

from app.services.auth_rate_limit_service import (
    LoginRateLimitExceeded,
    RateLimitUnavailable,
)


router = APIRouter(prefix="/auth", tags=["Authentication"])

SESSION_COOKIE = "__Host-intelsoc_session"


class LoginRequest(BaseModel):
    email: str = Field(min_length=1, max_length=254)
    password: str = Field(min_length=1, max_length=128)


def require_trusted_origin(request: Request):
    """Reject state-changing requests from untrusted origins."""

    trusted = os.getenv(
        "INTELSOC_DASHBOARD_ORIGIN", ""
    ).strip()

    parsed = urlsplit(trusted)

    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        raise HTTPException(
            status_code=503,
            detail="Dashboard authentication not configured",
        )

    if request.headers.get("origin") != trusted:
        raise HTTPException(
            status_code=403,
            detail="Untrusted request origin",
        )


def get_source_ip(request: Request):
    return request.client.host if request.client else None


def disable_cache(response: Response):
    response.headers["Cache-Control"] = "no-store"


@router.post("/login")
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
):
    require_trusted_origin(request)

    try:
        result = authenticate_user(
            email=payload.email,
            password=payload.password,
            source_ip=get_source_ip(request),
        )

    except InvalidCredentials:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password",
        )

    except LoginRateLimitExceeded as error:
        raise HTTPException(
            status_code=429,
            detail="Too many login attempts",
            headers={
                "Retry-After": str(error.retry_after)
            },
        )

    except (
        RateLimitUnavailable,
        AuthenticationBusy,
        psycopg.Error,
    ):
        raise HTTPException(
            status_code=503,
            detail="Authentication temporarily unavailable",
        )

    response.set_cookie(
        key=SESSION_COOKIE,
        value=result["session_token"],
        max_age=SESSION_LIFETIME_SECONDS,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
    )

    disable_cache(response)

    return {
        "user": result["user"],
        "expires_at": result["expires_at"],
    }


@router.get("/me")
def current_user(
    request: Request,
    response: Response,
):
    token = request.cookies.get(SESSION_COOKIE)

    try:
        session = validate_session(token)

    except InvalidSession:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired session",
        )

    except psycopg.Error:
        raise HTTPException(
            status_code=503,
            detail="Authentication temporarily unavailable",
        )

    disable_cache(response)

    return {
        "user_id": session["user_id"],
        "username": session["username"],
        "email": session["email"],
        "role": session["role"],
        "status": session["status"],
        "expires_at": session["expires_at"],
    }


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
):
    require_trusted_origin(request)

    token = request.cookies.get(SESSION_COOKIE)

    if token:
        try:
            revoke_session(
                token,
                source_ip=get_source_ip(request),
            )

        except InvalidSession:
            pass

        except psycopg.Error:
            raise HTTPException(
                status_code=503,
                detail="Logout temporarily unavailable",
            )

    response.delete_cookie(
        key=SESSION_COOKIE,
        path="/",
        secure=True,
        httponly=True,
        samesite="strict",
    )

    disable_cache(response)

    return {"status": "logged_out"}
