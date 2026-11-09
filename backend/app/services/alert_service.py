from dataclasses import dataclass
from pathlib import Path
from uuid import UUID, uuid4

import psycopg
from dotenv import load_dotenv

from app.core.config import get_postgres_config


ROOT = Path(__file__).resolve().parents[3]
load_dotenv(ROOT / ".env")


@dataclass(frozen=True)
class PersistedAlert:
    alert_id: UUID
    detection_id: UUID
    created: bool


def create_alert_for_detection(
    detection_id: UUID | str,
) -> PersistedAlert:
    """
    Create one analyst-facing alert for a persisted detection.

    detection_id is UNIQUE in security_alerts, so retries and worker
    restarts reuse the existing alert instead of creating duplicates.
    """

    detection_id = UUID(str(detection_id))
    new_alert_id = uuid4()

    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO security_alerts (
                    alert_id,
                    detection_id,
                    rule_id,
                    title,
                    severity,
                    status,
                    device_id,
                    target_user,
                    source_ip
                )
                SELECT
                    %s,
                    d.detection_id,
                    d.rule_id,
                    d.rule_name,
                    d.severity,
                    'open',
                    d.device_id,
                    d.target_user,
                    d.source_ip
                FROM detections AS d
                WHERE d.detection_id = %s
                ON CONFLICT (detection_id)
                DO NOTHING
                RETURNING alert_id
                """,
                (
                    new_alert_id,
                    detection_id,
                ),
            )

            inserted = cursor.fetchone()

            if inserted is not None:
                return PersistedAlert(
                    alert_id=inserted[0],
                    detection_id=detection_id,
                    created=True,
                )

            cursor.execute(
                """
                SELECT alert_id
                FROM security_alerts
                WHERE detection_id = %s
                """,
                (detection_id,),
            )

            existing = cursor.fetchone()

            if existing is not None:
                return PersistedAlert(
                    alert_id=existing[0],
                    detection_id=detection_id,
                    created=False,
                )

            cursor.execute(
                """
                SELECT 1
                FROM detections
                WHERE detection_id = %s
                """,
                (detection_id,),
            )

            if cursor.fetchone() is None:
                raise ValueError(
                    f"Detection does not exist: {detection_id}"
                )

            raise RuntimeError(
                "Alert insert returned no row and no existing alert "
                "was found"
            )


def update_alert_status(
    alert_id: UUID | str,
    status: str,
    *,
    resolution_note: str | None = None,
) -> bool:
    """
    Update the lifecycle state of an existing alert.

    Returns False if alert_id does not exist. Resolution metadata is
    recorded only for resolved/false-positive states.
    """

    allowed = {
        "open",
        "acknowledged",
        "resolved",
        "false_positive",
    }

    status = str(status).strip().lower()

    if status not in allowed:
        raise ValueError(
            f"Unsupported alert status: {status}"
        )

    note = (
        str(resolution_note).strip()[:4000]
        if resolution_note is not None
        else None
    )

    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE security_alerts
                SET
                    status = %s,
                    updated_at = NOW(),
                    acknowledged_at = CASE
                        WHEN %s = 'acknowledged'
                            THEN COALESCE(acknowledged_at, NOW())
                        ELSE acknowledged_at
                    END,
                    resolved_at = CASE
                        WHEN %s IN ('resolved', 'false_positive')
                            THEN NOW()
                        ELSE NULL
                    END,
                    resolution_note = CASE
                        WHEN %s IN ('resolved', 'false_positive')
                            THEN %s
                        ELSE NULL
                    END
                WHERE alert_id = %s
                """,
                (
                    status,
                    status,
                    status,
                    status,
                    note,
                    UUID(str(alert_id)),
                ),
            )

            return cursor.rowcount == 1
