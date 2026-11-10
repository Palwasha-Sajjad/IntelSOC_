import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import psycopg
from dotenv import load_dotenv

from app.core.config import get_postgres_config
from app.services.ti_provider_result import ProviderResult


ROOT = Path(__file__).resolve().parents[3]
load_dotenv(ROOT / ".env")


@dataclass(frozen=True)
class AlertEvidence:
    alert_id: UUID
    detection_id: UUID
    event_id: UUID
    source: str
    raw_event: dict[str, Any]


@dataclass(frozen=True)
class CachedTiResult:
    result_id: UUID
    provider: str
    indicator_type: str
    indicator_value: str
    verdict: str
    lookup_status: str
    confidence: int | None
    details: dict[str, Any]
    checked_at: datetime
    expires_at: datetime


def get_alert_evidence(
    alert_id: UUID | str,
) -> tuple[AlertEvidence, ...]:
    """Return only the events that actually contributed to an alert."""

    alert_id = UUID(str(alert_id))

    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    a.alert_id,
                    a.detection_id,
                    e.event_id,
                    e.source,
                    e.raw_event
                FROM security_alerts AS a
                JOIN detection_events AS de
                  ON de.detection_id = a.detection_id
                JOIN security_events AS e
                  ON e.event_id = de.event_id
                WHERE a.alert_id = %s
                ORDER BY e.event_time, e.event_id
                """,
                (alert_id,),
            )

            rows = cursor.fetchall()

    return tuple(
        AlertEvidence(
            alert_id=row[0],
            detection_id=row[1],
            event_id=row[2],
            source=row[3],
            raw_event=_coerce_json_object(row[4]),
        )
        for row in rows
    )


def get_cached_ti_result(
    provider: str,
    indicator_type: str,
    indicator_value: str,
    *,
    now: datetime | None = None,
) -> CachedTiResult | None:
    """Return one non-expired cached provider result."""

    current_time = now or datetime.now(timezone.utc)
    if current_time.tzinfo is None:
        raise ValueError("now must be timezone-aware")

    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    result_id,
                    provider,
                    indicator_type,
                    indicator_value,
                    verdict,
                    lookup_status,
                    confidence,
                    provider_data,
                    checked_at,
                    expires_at
                FROM ti_results
                WHERE provider = %s
                  AND indicator_type = %s
                  AND indicator_value = %s
                  AND expires_at > %s
                """,
                (
                    provider,
                    indicator_type,
                    indicator_value,
                    current_time,
                ),
            )

            row = cursor.fetchone()

    if row is None:
        return None

    return CachedTiResult(
        result_id=row[0],
        provider=row[1],
        indicator_type=row[2],
        indicator_value=row[3],
        verdict=row[4],
        lookup_status=row[5],
        confidence=row[6],
        details=_coerce_json_object(row[7]),
        checked_at=row[8],
        expires_at=row[9],
    )


def persist_ti_result(
    result: ProviderResult,
    *,
    checked_at: datetime,
    expires_at: datetime,
) -> UUID:
    """Insert or refresh the cache row for one provider+indicator."""

    _validate_result_times(checked_at, expires_at)
    result_id = uuid4()

    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO ti_results (
                    result_id,
                    provider,
                    indicator_type,
                    indicator_value,
                    verdict,
                    lookup_status,
                    confidence,
                    provider_data,
                    checked_at,
                    expires_at,
                    updated_at
                )
                VALUES (
                    %s, %s, %s, %s, %s,
                    %s, %s, %s::jsonb, %s, %s, NOW()
                )
                ON CONFLICT (
                    provider,
                    indicator_type,
                    indicator_value
                )
                DO UPDATE SET
                    verdict = EXCLUDED.verdict,
                    lookup_status = EXCLUDED.lookup_status,
                    confidence = EXCLUDED.confidence,
                    provider_data = EXCLUDED.provider_data,
                    checked_at = EXCLUDED.checked_at,
                    expires_at = EXCLUDED.expires_at,
                    updated_at = NOW()
                RETURNING result_id
                """,
                (
                    result_id,
                    result.provider,
                    result.indicator_type,
                    result.indicator_value,
                    result.verdict,
                    result.lookup_status,
                    result.confidence,
                    json.dumps(result.details),
                    checked_at,
                    expires_at,
                ),
            )

            row = cursor.fetchone()

    if row is None:
        raise RuntimeError("TI result upsert returned no result_id")

    return row[0]


def link_alert_indicator(
    *,
    alert_id: UUID | str,
    event_id: UUID | str,
    result_id: UUID | str,
) -> None:
    """Idempotently preserve which evidence event produced a TI result."""

    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO alert_ti_indicators (
                    alert_id,
                    event_id,
                    result_id
                )
                VALUES (%s, %s, %s)
                ON CONFLICT DO NOTHING
                """,
                (
                    UUID(str(alert_id)),
                    UUID(str(event_id)),
                    UUID(str(result_id)),
                ),
            )


def mark_alert_ti_processed(
    alert_id: UUID | str,
) -> None:
    """Record successful TI completion for one alert."""

    _upsert_alert_state(
        alert_id=alert_id,
        status="processed",
        error=None,
    )


def mark_alert_ti_failed(
    alert_id: UUID | str,
    error: str,
) -> None:
    """Record one failed TI attempt without losing retry state."""

    _upsert_alert_state(
        alert_id=alert_id,
        status="failed",
        error=str(error).strip()[:4000],
    )


def _upsert_alert_state(
    *,
    alert_id: UUID | str,
    status: str,
    error: str | None,
) -> None:
    alert_id = UUID(str(alert_id))

    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO alert_ti_analysis_state (
                    alert_id,
                    status,
                    attempts,
                    last_error,
                    processed_at,
                    updated_at
                )
                VALUES (
                    %s,
                    %s,
                    1,
                    %s,
                    CASE WHEN %s = 'processed' THEN NOW() ELSE NULL END,
                    NOW()
                )
                ON CONFLICT (alert_id)
                DO UPDATE SET
                    status = EXCLUDED.status,
                    attempts = alert_ti_analysis_state.attempts + 1,
                    last_error = EXCLUDED.last_error,
                    processed_at = CASE
                        WHEN EXCLUDED.status = 'processed' THEN NOW()
                        ELSE alert_ti_analysis_state.processed_at
                    END,
                    updated_at = NOW()
                """,
                (
                    alert_id,
                    status,
                    error,
                    status,
                ),
            )


def _validate_result_times(
    checked_at: datetime,
    expires_at: datetime,
) -> None:
    if checked_at.tzinfo is None or expires_at.tzinfo is None:
        raise ValueError("TI timestamps must be timezone-aware")

    if expires_at <= checked_at:
        raise ValueError("expires_at must be later than checked_at")


def _coerce_json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value

    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return decoded if isinstance(decoded, dict) else {}

    return {}
