from pathlib import Path
from uuid import uuid4

import psycopg
from dotenv import load_dotenv
from app.core.config import get_postgres_config


ROOT = Path(__file__).resolve().parents[3]
load_dotenv(ROOT / ".env")


SUPPORTED_PLATFORMS = {"windows", "linux"}
SUPPORTED_CRITICALITIES = {"low", "medium", "high"}


def validate_platform(platform: str) -> str:
    normalized = platform.strip().lower()

    if normalized not in SUPPORTED_PLATFORMS:
        raise ValueError(
            f"Unsupported platform: {platform}"
        )

    return normalized


def validate_criticality(criticality: str) -> str:
    normalized = criticality.strip().lower()

    if normalized not in SUPPORTED_CRITICALITIES:
        raise ValueError(
            f"Unsupported criticality: {criticality}"
        )

    return normalized


def register_device(
    hostname: str,
    platform: str,
) -> dict:
    """
    Register a new IntelSOC endpoint.

    Devices created through the protected enrollment endpoint are
    immediately active because enrollment itself is authenticated
    using INTELSOC_ENROLLMENT_TOKEN.

    Device criticality is intentionally not supplied by the endpoint.
    PostgreSQL assigns the safe default of 'medium' until an
    administrator explicitly changes it.
    """

    platform = validate_platform(platform)
    hostname = hostname.strip()

    if not hostname:
        raise ValueError("Hostname cannot be empty")

    device_id = uuid4()

    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO registered_devices (
                    device_id,
                    hostname,
                    platform,
                    status
                )
                VALUES (%s, %s, %s, 'active')
                RETURNING
                    device_id,
                    hostname,
                    platform,
                    status,
                    criticality,
                    created_at,
                    last_seen_at
                """,
                (
                    device_id,
                    hostname,
                    platform,
                ),
            )

            row = cursor.fetchone()

    return {
        "device_id": row[0],
        "hostname": row[1],
        "platform": row[2],
        "status": row[3],
        "criticality": row[4],
        "created_at": row[5],
        "last_seen_at": row[6],
    }


def get_device_by_id(device_id):
    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    device_id,
                    hostname,
                    platform,
                    status,
                    criticality,
                    created_at,
                    last_seen_at
                FROM registered_devices
                WHERE device_id = %s
                """,
                (device_id,),
            )

            row = cursor.fetchone()

    if row is None:
        return None

    return {
        "device_id": row[0],
        "hostname": row[1],
        "platform": row[2],
        "status": row[3],
        "criticality": row[4],
        "created_at": row[5],
        "last_seen_at": row[6],
    }


def update_device_criticality(
    device_id,
    criticality: str,
) -> dict | None:
    """
    Update only the administrator-controlled criticality classification
    for an existing registered device.
    """

    criticality = validate_criticality(criticality)

    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE registered_devices
                SET criticality = %s
                WHERE device_id = %s
                RETURNING
                    device_id,
                    hostname,
                    platform,
                    status,
                    criticality,
                    created_at,
                    last_seen_at
                """,
                (
                    criticality,
                    device_id,
                ),
            )

            row = cursor.fetchone()

    if row is None:
        return None

    return {
        "device_id": row[0],
        "hostname": row[1],
        "platform": row[2],
        "status": row[3],
        "criticality": row[4],
        "created_at": row[5],
        "last_seen_at": row[6],
    }


def update_device_last_seen(device_id) -> bool:
    """
    Record the last successful ingestion time for an active device.

    Failure to update this metadata must not interrupt event ingestion.
    """

    try:
        with psycopg.connect(
            **get_postgres_config(),
            connect_timeout=5,
        ) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE registered_devices
                    SET last_seen_at = NOW()
                    WHERE device_id = %s
                      AND status = 'active'
                    RETURNING device_id
                    """,
                    (device_id,),
                )

                row = cursor.fetchone()

        return row is not None

    except psycopg.Error:
        return False
