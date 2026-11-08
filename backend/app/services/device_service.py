import os
from pathlib import Path
from uuid import uuid4

import psycopg
from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parents[3]
load_dotenv(ROOT / ".env")


SUPPORTED_PLATFORMS = {"windows", "linux"}


def validate_platform(platform: str) -> str:
    normalized = platform.strip().lower()

    if normalized not in SUPPORTED_PLATFORMS:
        raise ValueError(
            f"Unsupported platform: {platform}"
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
    """

    platform = validate_platform(platform)
    hostname = hostname.strip()

    if not hostname:
        raise ValueError("Hostname cannot be empty")

    device_id = uuid4()

    with psycopg.connect(
        host="127.0.0.1",
        port=5433,
        dbname="intelsoc",
        user="intelsoc",
        password=os.environ["POSTGRES_PASSWORD"],
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
        "created_at": row[4],
        "last_seen_at": row[5],
    }


def get_device_by_id(device_id):
    with psycopg.connect(
        host="127.0.0.1",
        port=5433,
        dbname="intelsoc",
        user="intelsoc",
        password=os.environ["POSTGRES_PASSWORD"],
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
        "created_at": row[4],
        "last_seen_at": row[5],
    }
