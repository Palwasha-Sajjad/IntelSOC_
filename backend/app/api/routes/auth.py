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



# --------------------------------------------------
# Invitation-based account activation
# --------------------------------------------------

from typing import Literal

from app.services.auth_activation_service import (
    activate_account,
    InvalidInvitation,
)

from app.services.auth_rate_limit_service import (
    enforce_activation_rate_limit,
    ActivationRateLimitExceeded,
)

from app.services.auth_session_service import (
    PASSWORD_VERIFICATION_SLOTS,
)


class ActivateAccountRequest(BaseModel):
    invitation_token: str = Field(
        min_length=43,
        max_length=43,
        pattern=r"^[A-Za-z0-9_-]{43}$",
    )

    password: str = Field(
        min_length=15,
        max_length=128,
    )


class ActivateAccountResponse(BaseModel):
    status: Literal["activated"]
    message: str


@router.post(
    "/activate",
    response_model=ActivateAccountResponse,
)
def activate_invited_account(
    payload: ActivateAccountRequest,
    request: Request,
    response: Response,
):
    require_trusted_origin(request)

    source_ip = (
        request.client.host
        if request.client else None
    )

    try:
        enforce_activation_rate_limit(
            invitation_token=payload.invitation_token,
            source_ip=source_ip,
        )

        if not PASSWORD_VERIFICATION_SLOTS.acquire(
            blocking=False
        ):
            raise HTTPException(
                status_code=503,
                detail="Authentication temporarily unavailable",
                headers={"Cache-Control": "no-store"},
            )

        try:
            activate_account(
                invitation_token=payload.invitation_token,
                password=payload.password,
                source_ip=source_ip,
            )

        finally:
            PASSWORD_VERIFICATION_SLOTS.release()

    except ActivationRateLimitExceeded as exc:
        raise HTTPException(
            status_code=429,
            detail="Too many activation attempts",
            headers={
                "Retry-After": str(exc.retry_after),
                "Cache-Control": "no-store",
            },
        ) from None

    except InvalidInvitation:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired invitation",
            headers={"Cache-Control": "no-store"},
        ) from None

    except ValueError:
        raise HTTPException(
            status_code=422,
            detail="Password does not meet security requirements",
            headers={"Cache-Control": "no-store"},
        ) from None

    except (
        RateLimitUnavailable,
        psycopg.Error,
        OSError,
        KeyError,
    ):
        raise HTTPException(
            status_code=503,
            detail="Account activation temporarily unavailable",
            headers={"Cache-Control": "no-store"},
        ) from None

    response.headers["Cache-Control"] = "no-store"

    return {
        "status": "activated",
        "message": "Account activated successfully. Please log in.",
    }
