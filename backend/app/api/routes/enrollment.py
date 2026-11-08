import os
import secrets

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field

from app.services.device_service import register_device


router = APIRouter(
    prefix="/devices",
    tags=["device-enrollment"],
)


class EnrollmentRequest(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    platform: str = Field(pattern="^(windows|linux)$")


class EnrollmentResponse(BaseModel):
    device_id: str
    hostname: str
    platform: str
    ingest_key: str


def verify_enrollment_token(
    submitted_token: str | None = Header(
        default=None,
        alias="X-IntelSOC-Enrollment-Token",
    ),
) -> None:
    expected_token = os.getenv("INTELSOC_ENROLLMENT_TOKEN")

    if not expected_token:
        raise HTTPException(
            status_code=503,
            detail="Device enrollment is not configured",
        )

    if not submitted_token or not secrets.compare_digest(
        submitted_token,
        expected_token,
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing enrollment token",
        )


@router.post(
    "/enroll",
    response_model=EnrollmentResponse,
    status_code=201,
    dependencies=[Depends(verify_enrollment_token)],
)
def enroll_device(request: EnrollmentRequest):
    ingest_key = os.getenv("INTELSOC_INGEST_API_KEY")

    if not ingest_key:
        raise HTTPException(
            status_code=503,
            detail="Ingestion authentication not configured",
        )

    device = register_device(
        hostname=request.hostname,
        platform=request.platform,
    )

    return EnrollmentResponse(
        device_id=str(device["device_id"]),
        hostname=device["hostname"],
        platform=device["platform"],
        ingest_key=ingest_key,
    )
