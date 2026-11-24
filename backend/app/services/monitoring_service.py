"""Read-only data retrieval for the IntelSOC monitoring interface."""

import psycopg
from psycopg.rows import dict_row

from app.core.config import get_postgres_config


def _fetch_rows(query, params):
    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
        row_factory=dict_row,
    ) as conn:
        with conn.cursor() as cur:
            cur.execute("SET TRANSACTION READ ONLY")
            cur.execute(query, params)
            return list(cur.fetchall())


def _validate_pagination(limit, offset):
    if not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")

    if not 0 <= offset <= 100000:
        raise ValueError("offset must be between 0 and 100000")


def list_events(
    *,
    limit=50,
    offset=0,
    hostname=None,
    event_type=None,
    device_id=None,
):
    _validate_pagination(limit, offset)

    return _fetch_rows(
        """
        SELECT
            event_id,
            device_id,
            hostname,
            source,
            event_type,
            src_ip,
            event_time,
            received_at
        FROM public.security_events
        WHERE (%s::text IS NULL OR hostname = %s)
          AND (%s::text IS NULL OR event_type = %s)
          AND (%s::uuid IS NULL OR device_id = %s)
        ORDER BY event_time DESC, event_id DESC
        LIMIT %s OFFSET %s
        """,
        (
            hostname, hostname,
            event_type, event_type,
            device_id, device_id,
            limit, offset,
        ),
    )


def list_alerts(
    *,
    limit=50,
    offset=0,
    severity=None,
    status=None,
    device_id=None,
):
    _validate_pagination(limit, offset)

    return _fetch_rows(
        """
        SELECT
            a.alert_id,
            a.detection_id,
            a.rule_id,
            a.title,
            a.severity,
            a.status,
            a.device_id,
            d.hostname,
            a.target_user,
            a.source_ip,
            a.created_at,
            a.updated_at,
            r.rule_score,
            r.ti_score,
            r.lanobert_score,
            r.overall_score,
            r.classification,
            r.assessment_status,
            r.score_version
        FROM public.security_alerts a
        LEFT JOIN public.registered_devices d
            ON d.device_id = a.device_id
        LEFT JOIN public.alert_risk_assessments r
            ON r.alert_id = a.alert_id
        WHERE (%s::text IS NULL OR a.severity = %s)
          AND (%s::text IS NULL OR a.status = %s)
          AND (%s::uuid IS NULL OR a.device_id = %s)
        ORDER BY a.created_at DESC, a.alert_id DESC
        LIMIT %s OFFSET %s
        """,
        (
            severity, severity,
            status, status,
            device_id, device_id,
            limit, offset,
        ),
    )


def list_incidents(
    *,
    limit=50,
    offset=0,
    severity=None,
    status=None,
    device_id=None,
):
    _validate_pagination(limit, offset)

    return _fetch_rows(
        """
        SELECT
            i.incident_id,
            i.title,
            i.severity,
            i.status,
            i.device_id,
            d.hostname,
            i.target_user,
            i.source_ip,
            i.first_seen_at,
            i.last_seen_at,
            i.created_at,
            i.updated_at,
            (
                SELECT COUNT(*)
                FROM public.incident_alerts ia
                WHERE ia.incident_id = i.incident_id
            ) AS alert_count
        FROM public.incidents i
        LEFT JOIN public.registered_devices d
            ON d.device_id = i.device_id
        WHERE (%s::text IS NULL OR i.severity = %s)
          AND (%s::text IS NULL OR i.status = %s)
          AND (%s::uuid IS NULL OR i.device_id = %s)
        ORDER BY i.last_seen_at DESC, i.incident_id DESC
        LIMIT %s OFFSET %s
        """,
        (
            severity, severity,
            status, status,
            device_id, device_id,
            limit, offset,
        ),
    )
