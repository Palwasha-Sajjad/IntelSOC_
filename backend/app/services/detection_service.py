import hashlib
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID, uuid4

import psycopg
from dotenv import load_dotenv

from app.analysis.detection_candidate import DetectionCandidateLike
from app.core.config import get_postgres_config


ROOT = Path(__file__).resolve().parents[3]
load_dotenv(ROOT / ".env")


@dataclass(frozen=True)
class PersistedDetection:
    detection_id: UUID
    fingerprint: str
    created: bool


_ALLOWED_SEVERITIES = {
    "informational", "low", "medium", "high", "critical",
}


def _validate_candidate(candidate: DetectionCandidateLike) -> None:
    """Reject incomplete or conflicting evidence before any database write."""
    if (
        not candidate.rule_id
        or not candidate.rule_id.strip()
        or not candidate.rule_name
        or not candidate.rule_name.strip()
        or not candidate.grouping_basis
        or not candidate.grouping_basis.strip()
    ):
        raise ValueError("Detection requires rule identity and grouping basis")
    if candidate.severity not in _ALLOWED_SEVERITIES:
        raise ValueError("Invalid detection severity")
    if not candidate.event_ids or len(set(candidate.event_ids)) != len(candidate.event_ids):
        raise ValueError("Detection evidence IDs must be non-empty and unique")
    if candidate.event_count != len(candidate.event_ids):
        raise ValueError("Detection evidence count does not match event IDs")
    if any(not str(event_id).strip() for event_id in candidate.event_ids):
        raise ValueError("Detection evidence IDs cannot be empty")
    if (
        candidate.window_start.tzinfo is None
        or candidate.window_end.tzinfo is None
        or candidate.window_start > candidate.window_end
    ):
        raise ValueError("Detection time window must be timezone-aware and ordered")


def build_detection_fingerprint(
    candidate: DetectionCandidateLike,
) -> str:
    """
    Build a stable fingerprint for one detection episode.

    The contributing event IDs are sorted so the same evidence set
    produces the same fingerprint regardless of caller ordering.
    """

    _validate_candidate(candidate)
    evidence = "|".join(
        sorted(str(event_id) for event_id in candidate.event_ids)
    )

    material = "|".join(
        (
            candidate.rule_id,
            candidate.device_id,
            (candidate.target_user or "").casefold(),
            candidate.source_ip or "",
            str(candidate.logon_type or ""),
            candidate.grouping_basis,
            candidate.window_start.isoformat(),
            candidate.window_end.isoformat(),
            evidence,
        )
    )

    return hashlib.sha256(
        material.encode("utf-8")
    ).hexdigest()


def persist_detection(
    candidate: DetectionCandidateLike,
) -> PersistedDetection:
    """
    Persist one rule result and its evidence links idempotently.

    A duplicate fingerprint returns the existing detection rather
    than creating a second record.
    """

    fingerprint = build_detection_fingerprint(candidate)
    new_detection_id = uuid4()

    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO detections (
                    detection_id,
                    rule_id,
                    rule_name,
                    severity,
                    device_id,
                    target_user,
                    source_ip,
                    logon_type,
                    grouping_basis,
                    fingerprint,
                    event_count,
                    window_start,
                    window_end
                )
                VALUES (
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s,
                    %s, %s, %s
                )
                ON CONFLICT (fingerprint)
                DO NOTHING
                RETURNING detection_id
                """,
                (
                    new_detection_id,
                    candidate.rule_id,
                    candidate.rule_name,
                    candidate.severity,
                    candidate.device_id,
                    candidate.target_user,
                    candidate.source_ip,
                    candidate.logon_type,
                    candidate.grouping_basis,
                    fingerprint,
                    candidate.event_count,
                    candidate.window_start,
                    candidate.window_end,
                ),
            )

            inserted = cursor.fetchone()

            if inserted is not None:
                detection_id = inserted[0]
                created = True
            else:
                cursor.execute(
                    """
                    SELECT detection_id
                    FROM detections
                    WHERE fingerprint = %s
                    """,
                    (fingerprint,),
                )

                existing = cursor.fetchone()

                if existing is None:
                    raise RuntimeError(
                        "Detection conflict occurred but "
                        "existing row was not found"
                    )

                detection_id = existing[0]
                created = False

            for event_id in candidate.event_ids:
                cursor.execute(
                    """
                    INSERT INTO detection_events (
                        detection_id,
                        event_id
                    )
                    VALUES (%s, %s)
                    ON CONFLICT DO NOTHING
                    """,
                    (
                        detection_id,
                        event_id,
                    ),
                )

    return PersistedDetection(
        detection_id=detection_id,
        fingerprint=fingerprint,
        created=created,
    )


def mark_event_analysis_processed(
    event_id: UUID | str,
    rule_id: str = "RULE-WIN-001",
) -> None:
    """Mark one event complete for one rule, without affecting other rules."""

    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO event_rule_analysis_state (
                    event_id,
                    rule_id,
                    status,
                    attempts,
                    processed_at,
                    updated_at
                )
                VALUES (%s, %s, 'processed', 1, NOW(), NOW())
                ON CONFLICT (event_id, rule_id)
                DO UPDATE SET
                    status = 'processed',
                    attempts = event_rule_analysis_state.attempts + 1,
                    last_error = NULL,
                    processed_at = NOW(),
                    updated_at = NOW()
                """,
                (event_id, rule_id),
            )


def mark_event_analysis_failed(
    event_id: UUID | str,
    error: str,
    rule_id: str = "RULE-WIN-001",
) -> None:
    """Record a failed attempt for one rule without affecting other rules."""

    error = str(error).strip()[:4000]

    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO event_rule_analysis_state (
                    event_id,
                    rule_id,
                    status,
                    attempts,
                    last_error,
                    updated_at
                )
                VALUES (%s, %s, 'failed', 1, %s, NOW())
                ON CONFLICT (event_id, rule_id)
                DO UPDATE SET
                    status = 'failed',
                    attempts = event_rule_analysis_state.attempts + 1,
                    last_error = EXCLUDED.last_error,
                    updated_at = NOW()
                """,
                (
                    event_id,
                    rule_id,
                    error,
                ),
            )
