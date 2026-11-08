import os
import secrets
from pathlib import Path

from dotenv import load_dotenv
from fastapi import Header, HTTPException, Security
from fastapi.security import APIKeyHeader

from app.services.device_service import get_device_by_id


ROOT_DIR = Path(__file__).resolve().parents[3]
load_dotenv(ROOT_DIR / ".env")


api_key_header = APIKeyHeader(
    name="X-IntelSOC-Key",
    auto_error=False,
)


def verify_ingest_key(
    submitted_key: str | None = Security(api_key_header),
) -> None:
    """
    Validate the shared IntelSOC ingestion API key.
    """

    expected_key = os.getenv("INTELSOC_INGEST_API_KEY")

    if not expected_key:
        raise HTTPException(
            status_code=503,
            detail="Ingestion authentication not configured",
        )

    if not submitted_key or not secrets.compare_digest(
        submitted_key,
        expected_key,
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing ingestion API key",
        )


def verify_registered_device(
    submitted_device_id: str | None,
) -> dict:
    """
    Validate an IntelSOC endpoint using only its registered device ID.

    Certificate CN and fingerprint authentication are intentionally
    not used in the final Module 1 architecture.
    """

    if not submitted_device_id:
        raise HTTPException(
            status_code=401,
            detail="Missing device ID",
        )

    device = get_device_by_id(submitted_device_id)

    if device is None:
        raise HTTPException(
            status_code=401,
            detail="Unknown device",
        )

    if str(device.get("device_id")) != str(submitted_device_id):
        raise HTTPException(
            status_code=401,
            detail="Device identity mismatch",
        )

    if device.get("status") != "active":
        raise HTTPException(
            status_code=401,
            detail="Device is not active",
        )

    return device


def verify_ingest_device(
    submitted_device_id: str | None = Header(
        default=None,
        alias="X-Device-ID",
    ),
) -> dict:
    """
    Authenticate an ingestion endpoint using X-Device-ID.
    """

    return verify_registered_device(
        submitted_device_id=submitted_device_id,
    )
