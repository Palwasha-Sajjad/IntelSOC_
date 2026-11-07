import os
import secrets
from pathlib import Path

from dotenv import load_dotenv
from fastapi import Header, HTTPException, Security
from fastapi.security import APIKeyHeader

from app.services.device_service import get_device_by_id


# Load IntelSOC's existing root .env file.
ROOT_DIR = Path(__file__).resolve().parents[3]
load_dotenv(ROOT_DIR / ".env")


api_key_header = APIKeyHeader(
    name="X-IntelSOC-Key",
    auto_error=False,
)


def verify_ingest_key(
    submitted_key: str | None = Security(api_key_header),
) -> None:
    expected_key = os.getenv("INTELSOC_INGEST_API_KEY")

    # Fail closed if authentication is not configured.
    if not expected_key:
        raise HTTPException(
            status_code=503,
            detail="Ingestion authentication not configured",
        )

    if not submitted_key or not secrets.compare_digest(
        submitted_key, expected_key
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing ingestion API key",
        )


def verify_registered_device(
    submitted_device_id: str | None,
) -> dict:
    if not submitted_device_id:
        raise HTTPException(
            status_code=401,
            detail="Missing device identity",
        )

    device = get_device_by_id(submitted_device_id)

    if device is None:
        raise HTTPException(
            status_code=401,
            detail="Unknown device",
        )

    if device.get("status") != "active":
        raise HTTPException(
            status_code=401,
            detail="Inactive device",
        )

    return device


def verify_ingest_device(
    submitted_device_id: str | None = Header(
        default=None,
        alias="X-Device-ID",
    ),
) -> dict:
    """
    Validate that the endpoint is a registered active IntelSOC device.
    """
    return verify_registered_device(
        submitted_device_id=submitted_device_id,
    )
