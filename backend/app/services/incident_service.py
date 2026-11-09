import hashlib
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from uuid import UUID, uuid4

import psycopg
from dotenv import load_dotenv

from app.core.config import get_postgres_config


ROOT = Path(__file__).resolve().parents[3]
load_dotenv(ROOT / ".env")

CORRELATION_WINDOW = timedelta(minutes=30)

_SEVERITY_RANK = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass(frozen=True)
class PersistedIncident:
    incident_id: UUID
    alert_id: UUID
    created: bool
    linked: bool


def build_incident_correlation_key(
    *,
    device_id: UUID | str | None,
    target_user: str | None,
    source_ip: str | None,
) -> str:
    """
    Build a stable privacy-preserving key for incident correlation.

    Current policy correlates alerts by device + target user + source IP
    when a source IP exists. Local/no-IP activity correlates by device
    + target user.
    """

    device = str(device_id or "").strip().lower()
    user = str(target_user or "").strip().casefold()
    source = str(source_ip or "").strip().lower()

    material = "|".join(
        (
            device,
            user,
            source,
        )
    )

    return hashlib.sha256(
        material.encode("utf-8")
    ).hexdigest()


def correlate_alert_to_incident(
    alert_id: UUID | str,
    *,
    window: timedelta = CORRELATION_WINDOW,
) -> PersistedIncident:
    """
    Link one alert to an existing recent active incident or create one.

    Each alert can belong to only one incident. Reprocessing the same alert
    returns its existing incident and does not create duplicate history.
    """

    if window <= timedelta(0):
        raise ValueError("correlation window must be positive")

    alert_id = UUID(str(alert_id))

    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT incident_id
                FROM incident_alerts
                WHERE alert_id = %s
                """,
                (alert_id,),
            )

            existing_link = cursor.fetchone()

            if existing_link is not None:
                return PersistedIncident(
                    incident_id=existing_link[0],
                    alert_id=alert_id,
                    created=False,
                    linked=False,
                )

            cursor.execute(
                """
                SELECT
                    alert_id,
                    rule_id,
                    title,
                    severity,
                    device_id,
                    target_user,
                    source_ip,
                    created_at
                FROM security_alerts
                WHERE alert_id = %s
                """,
                (alert_id,),
            )

            alert = cursor.fetchone()

            if alert is None:
                raise ValueError(
                    f"Alert does not exist: {alert_id}"
                )

            (
                _,
                rule_id,
                alert_title,
                severity,
                device_id,
                target_user,
                source_ip,
                alert_created_at,
            ) = alert

            # One-off security control changes must not merge with credential
            # attack episodes just because they share device/user data.
            # Likewise, unrelated
            # alerts lacking any subject/IP must never be conflated.
            if rule_id in {"RULE-WIN-002", "RULE-WIN-003"} or (
                not target_user and not source_ip
            ):
                correlation_key = hashlib.sha256(
                    f"isolated|{rule_id}|{alert_id}".encode("utf-8")
                ).hexdigest()
            else:
                correlation_key = build_incident_correlation_key(
                    device_id=device_id,
                    target_user=target_user,
                    source_ip=source_ip,
                )

            cursor.execute(
                """
                SELECT
                    incident_id,
                    severity
                FROM incidents
                WHERE correlation_key = %s
                  AND status IN ('open', 'investigating')
                  AND last_seen_at >= %s
                ORDER BY last_seen_at DESC, created_at DESC
                LIMIT 1
                FOR UPDATE
                """,
                (
                    correlation_key,
                    alert_created_at - window,
                ),
            )

            existing_incident = cursor.fetchone()

            if existing_incident is None:
                incident_id = uuid4()
                incident_title = _incident_title(
                    rule_id=rule_id,
                    alert_title=alert_title,
                    target_user=target_user,
                    source_ip=source_ip,
                )

                cursor.execute(
                    """
                    INSERT INTO incidents (
                        incident_id,
                        correlation_key,
                        title,
                        severity,
                        status,
                        device_id,
                        target_user,
                        source_ip,
                        first_seen_at,
                        last_seen_at
                    )
                    VALUES (
                        %s, %s, %s, %s, 'open',
                        %s, %s, %s, %s, %s
                    )
                    """,
                    (
                        incident_id,
                        correlation_key,
                        incident_title,
                        severity,
                        device_id,
                        target_user,
                        source_ip,
                        alert_created_at,
                        alert_created_at,
                    ),
                )

                created = True

                _append_history(
                    cursor,
                    incident_id=incident_id,
                    event_type="created",
                    details=(
                        f"Incident created from alert {alert_id}."
                    ),
                )
            else:
                incident_id, incident_severity = existing_incident
                created = False

                escalated = _higher_severity(
                    incident_severity,
                    severity,
                )

                cursor.execute(
                    """
                    UPDATE incidents
                    SET
                        severity = %s,
                        last_seen_at = GREATEST(last_seen_at, %s),
                        updated_at = NOW()
                    WHERE incident_id = %s
                    """,
                    (
                        escalated,
                        alert_created_at,
                        incident_id,
                    ),
                )

                if escalated != incident_severity:
                    _append_history(
                        cursor,
                        incident_id=incident_id,
                        event_type="severity_changed",
                        details=(
                            f"Severity changed from "
                            f"{incident_severity} to {escalated}."
                        ),
                    )

            cursor.execute(
                """
                INSERT INTO incident_alerts (
                    incident_id,
                    alert_id
                )
                VALUES (%s, %s)
                ON CONFLICT (alert_id)
                DO NOTHING
                RETURNING alert_id
                """,
                (
                    incident_id,
                    alert_id,
                ),
            )

            linked = cursor.fetchone() is not None

            if linked:
                _append_history(
                    cursor,
                    incident_id=incident_id,
                    event_type="alert_linked",
                    details=f"Alert linked: {alert_id}.",
                )

            return PersistedIncident(
                incident_id=incident_id,
                alert_id=alert_id,
                created=created,
                linked=linked,
            )


def update_incident_status(
    incident_id: UUID | str,
    status: str,
    *,
    resolution_note: str | None = None,
) -> bool:
    """Update incident lifecycle and append an auditable history record."""

    allowed = {
        "open",
        "investigating",
        "resolved",
        "false_positive",
    }

    status = str(status).strip().lower()

    if status not in allowed:
        raise ValueError(
            f"Unsupported incident status: {status}"
        )

    note = (
        str(resolution_note).strip()[:4000]
        if resolution_note is not None
        else None
    )

    incident_id = UUID(str(incident_id))

    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE incidents
                SET
                    status = %s,
                    updated_at = NOW(),
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
                WHERE incident_id = %s
                """,
                (
                    status,
                    status,
                    status,
                    note,
                    incident_id,
                ),
            )

            if cursor.rowcount != 1:
                return False

            _append_history(
                cursor,
                incident_id=incident_id,
                event_type="status_changed",
                details=(
                    f"Incident status changed to {status}."
                    + (
                        f" Note: {note}"
                        if note
                        else ""
                    )
                ),
            )

            return True


def _incident_title(
    *,
    rule_id: str,
    alert_title: str,
    target_user: str | None,
    source_ip: str | None,
) -> str:
    subject = str(target_user or "").strip()

    if source_ip:
        subject = (
            f"{subject} from {source_ip}"
            if subject
            else str(source_ip)
        )

    if subject:
        return f"{alert_title}: {subject}"[:255]

    return f"{rule_id}: {alert_title}"[:255]


def _higher_severity(
    first: str,
    second: str,
) -> str:
    return (
        second
        if _SEVERITY_RANK[second] > _SEVERITY_RANK[first]
        else first
    )


def _append_history(
    cursor,
    *,
    incident_id: UUID,
    event_type: str,
    details: str | None,
) -> None:
    cursor.execute(
        """
        INSERT INTO incident_history (
            history_id,
            incident_id,
            event_type,
            details
        )
        VALUES (%s, %s, %s, %s)
        """,
        (
            uuid4(),
            incident_id,
            event_type,
            details,
        ),
    )
