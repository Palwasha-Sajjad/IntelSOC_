
import os
import secrets
from pathlib import Path

from dotenv import load_dotenv
from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader


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
