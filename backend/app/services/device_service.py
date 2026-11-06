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
    certificate_common_name: str,
) -> dict:
    platform = validate_platform(platform)

    hostname = hostname.strip()
    certificate_common_name = certificate_common_name.strip()

    if not hostname:
        raise ValueError("Hostname cannot be empty")

    if not certificate_common_name:
        raise ValueError(
            "Certificate common name cannot be empty"
        )

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
                    certificate_common_name,
                    certificate_fingerprint,
                    status
                )
                VALUES (%s, %s, %s, %s, NULL, 'pending')
                RETURNING
                    device_id,
                    hostname,
                    platform,
                    certificate_common_name,
                    certificate_fingerprint,
                    status
                """,
                (
                    device_id,
                    hostname,
                    platform,
                    certificate_common_name,
                ),
            )

            row = cursor.fetchone()

    return {
        "device_id": row[0],
        "hostname": row[1],
        "platform": row[2],
        "certificate_common_name": row[3],
        "certificate_fingerprint": row[4],
        "status": row[5],
    }

def activate_device(
    device_id,
    certificate_fingerprint: str,
) -> dict:
    fingerprint = certificate_fingerprint.strip()

    if not fingerprint:
        raise ValueError(
            "Certificate fingerprint cannot be empty"
        )

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
                UPDATE registered_devices
                SET
                    certificate_fingerprint = %s,
                    status = 'active'
                WHERE device_id = %s
                  AND status = 'pending'
                RETURNING
                    device_id,
                    hostname,
                    platform,
                    certificate_common_name,
                    certificate_fingerprint,
                    status
                """,
                (
                    fingerprint,
                    device_id,
                ),
            )

            row = cursor.fetchone()

    if row is None:
        raise ValueError(
            "Pending registered device not found"
        )

    return {
        "device_id": row[0],
        "hostname": row[1],
        "platform": row[2],
        "certificate_common_name": row[3],
        "certificate_fingerprint": row[4],
        "status": row[5],
    }


def validate_device_identity(
    device: dict,
    submitted_device_id: str,
    certificate_common_name: str,
    certificate_fingerprint: str,
) -> bool:
    if device.get("status") != "active":
        return False

    if str(device.get("device_id")) != str(submitted_device_id):
        return False

    if (
        device.get("certificate_common_name")
        != certificate_common_name
    ):
        return False

    if (
        device.get("certificate_fingerprint")
        != certificate_fingerprint
    ):
        return False

    return True

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
                    certificate_common_name,
                    certificate_fingerprint,
                    status
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
        "certificate_common_name": row[3],
        "certificate_fingerprint": row[4],
        "status": row[5],
    }
