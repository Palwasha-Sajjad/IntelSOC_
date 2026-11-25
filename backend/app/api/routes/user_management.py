"""Administrator-only user management API."""

from datetime import datetime
from typing import Literal
from uuid import UUID

import psycopg

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from app.api.rbac import require_administrator

from app.services.user_management_service import (
    list_users,
    get_user,
)


router = APIRouter(
    prefix="/users",
    tags=["User Management"],
    dependencies=[Depends(require_administrator)],
)


class UserResponse(BaseModel):
    user_id: UUID
    username: str
    email: str
    role: Literal["viewer", "analyst", "administrator"]
    status: Literal[
        "invited",
        "active",
        "suspended",
        "deactivated",
    ]
    created_by: UUID | None
    created_at: datetime
    updated_at: datetime
    last_login_at: datetime | None
    password_changed_at: datetime | None


@router.get("", response_model=list[UserResponse])
def read_users(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=100000),
    role: Literal[
        "viewer",
        "analyst",
        "administrator",
    ] | None = None,
    status: Literal[
        "invited",
        "active",
        "suspended",
        "deactivated",
    ] | None = None,
):
    try:
        return list_users(
            limit=limit,
            offset=offset,
            role=role,
            status=status,
        )

    except (psycopg.Error, OSError, KeyError):
        raise HTTPException(
            status_code=503,
            detail="User management temporarily unavailable",
        ) from None


@router.get("/{user_id}", response_model=UserResponse)
def read_user(user_id: UUID):
    try:
        user = get_user(user_id=user_id)

    except (psycopg.Error, OSError, KeyError):
        raise HTTPException(
            status_code=503,
            detail="User management temporarily unavailable",
        ) from None

    if user is None:
        raise HTTPException(
            status_code=404,
            detail="User not found",
        )

    return user


from app.services.auth_provisioning_service import (
    provision_user,
    deliver_invitation,
)

from app.services.auth_invitation_service import (
    InvitationUserNotFound,
    InvitationNotAllowed,
)

from app.services.user_management_service import (
    DuplicateUserError,
    UserManagementForbidden,
)

from app.services.email_service import EmailConfigurationError

from app.services.auth_rate_limit_service import (
    ProvisioningRateLimitExceeded,
    RateLimitUnavailable,
)


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    email: str = Field(min_length=3, max_length=254)
    role: Literal["viewer", "analyst", "administrator"]


class ProvisionUserResponse(BaseModel):
    user: UserResponse
    invitation_expires_at: datetime | None
    email_delivery: Literal["submitted", "unconfirmed"]
    audit_recorded: bool


class ResendInvitationResponse(BaseModel):
    user_id: UUID
    invitation_expires_at: datetime | None
    email_delivery: Literal["submitted", "unconfirmed"]
    audit_recorded: bool


def provisioning_error(exc):

    if isinstance(exc, ProvisioningRateLimitExceeded):
        return HTTPException(
            status_code=429,
            detail="Too many provisioning requests",
            headers={
                "Retry-After": str(exc.retry_after),
                "Cache-Control": "no-store",
            },
        )

    if isinstance(exc, RateLimitUnavailable):
        return HTTPException(
            status_code=503,
            detail="Account provisioning temporarily unavailable",
            headers={"Cache-Control": "no-store"},
        )

    if isinstance(exc, DuplicateUserError):
        return HTTPException(
            status_code=409,
            detail="Username or email already exists",
        )

    if isinstance(exc, UserManagementForbidden):
        return HTTPException(
            status_code=403,
            detail="Administrator authorization required",
        )

    if isinstance(exc, InvitationUserNotFound):
        return HTTPException(
            status_code=404,
            detail="User not found",
        )

    if isinstance(exc, InvitationNotAllowed):
        return HTTPException(
            status_code=409,
            detail="Account is not eligible for invitation",
        )

    if isinstance(exc, ValueError):
        return HTTPException(
            status_code=422,
            detail="Invalid account information",
        )

    return HTTPException(
        status_code=503,
        detail="Account provisioning temporarily unavailable",
    )


@router.post(
    "",
    status_code=201,
    response_model=ProvisionUserResponse,
)
def create_user_account(
    payload: CreateUserRequest,
    request: Request,
    administrator=Depends(require_administrator),
):
    try:
        result = provision_user(
            username=payload.username,
            email=payload.email,
            role=payload.role,
            actor_user_id=administrator["user_id"],
            source_ip=(
                request.client.host
                if request.client else None
            ),
        )

        result["user"].setdefault("last_login_at", None)
        result["user"].setdefault("password_changed_at", None)

        return result

    except (
        DuplicateUserError,
        UserManagementForbidden,
        InvitationUserNotFound,
        InvitationNotAllowed,
        EmailConfigurationError,
        ProvisioningRateLimitExceeded,
        RateLimitUnavailable,
        psycopg.Error,
        OSError,
        KeyError,
        ValueError,
    ) as exc:
        raise provisioning_error(exc) from None


@router.post(
    "/{user_id}/resend-invitation",
    response_model=ResendInvitationResponse,
)
def resend_user_invitation(
    user_id: UUID,
    request: Request,
    administrator=Depends(require_administrator),
):
    try:
        return deliver_invitation(
            user_id=user_id,
            actor_user_id=administrator["user_id"],
            source_ip=(
                request.client.host
                if request.client else None
            ),
        )

    except (
        UserManagementForbidden,
        InvitationUserNotFound,
        InvitationNotAllowed,
        EmailConfigurationError,
        ProvisioningRateLimitExceeded,
        RateLimitUnavailable,
        psycopg.Error,
        OSError,
        KeyError,
        ValueError,
    ) as exc:
        raise provisioning_error(exc) from None
