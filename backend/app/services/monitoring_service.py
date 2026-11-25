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


def get_alert_detail(*, alert_id):
    rows = _fetch_rows(
        """
        SELECT
            a.*,
            d.hostname,
            d.platform,
            d.criticality
        FROM public.security_alerts a
        LEFT JOIN public.registered_devices d
            ON d.device_id = a.device_id
        WHERE a.alert_id = %s
        """,
        (alert_id,),
    )

    return rows[0] if rows else None


def get_alert_ti(*, alert_id):
    if get_alert_detail(alert_id=alert_id) is None:
        return None

    return _fetch_rows(
        """
        SELECT
            t.result_id,
            t.provider,
            t.indicator_type,
            t.indicator_value,
            t.verdict,
            t.lookup_status,
            t.confidence,
            t.checked_at,
            t.expires_at,
            MAX(i.linked_at) AS linked_at,
            COUNT(DISTINCT i.event_id) AS linked_event_count
        FROM public.alert_ti_indicators i
        JOIN public.ti_results t
            ON t.result_id = i.result_id
        WHERE i.alert_id = %s
        GROUP BY
            t.result_id,
            t.provider,
            t.indicator_type,
            t.indicator_value,
            t.verdict,
            t.lookup_status,
            t.confidence,
            t.checked_at,
            t.expires_at
        ORDER BY linked_at DESC, t.result_id
        """,
        (alert_id,),
    )


def get_alert_risk(*, alert_id):
    if get_alert_detail(alert_id=alert_id) is None:
        return None

    rows = _fetch_rows(
        """
        SELECT
            alert_id,
            rule_score,
            ti_score,
            lanobert_score,
            overall_score,
            classification,
            assessment_status,
            evidence,
            score_version,
            assessed_at,
            updated_at
        FROM public.alert_risk_assessments
        WHERE alert_id = %s
        """,
        (alert_id,),
    )

    return {
        "alert_id": alert_id,
        "assessment": rows[0] if rows else None,
    }


def get_incident_detail(*, incident_id):
    rows = _fetch_rows(
        """
        SELECT
            i.*,
            d.hostname,
            d.platform,
            d.criticality
        FROM public.incidents i
        LEFT JOIN public.registered_devices d
            ON d.device_id = i.device_id
        WHERE i.incident_id = %s
        """,
        (incident_id,),
    )

    if not rows:
        return None

    incident = rows[0]

    alerts = _fetch_rows(
        """
        SELECT
            a.alert_id,
            a.rule_id,
            a.title,
            a.severity,
            a.status,
            a.created_at,
            r.overall_score,
            r.classification,
            ia.linked_at
        FROM public.incident_alerts ia
        JOIN public.security_alerts a
            ON a.alert_id = ia.alert_id
        LEFT JOIN public.alert_risk_assessments r
            ON r.alert_id = a.alert_id
        WHERE ia.incident_id = %s
        ORDER BY ia.linked_at DESC, a.alert_id
        LIMIT 100
        """,
        (incident_id,),
    )

    history = _fetch_rows(
        """
        SELECT
            history_id,
            event_type,
            details,
            created_at
        FROM public.incident_history
        WHERE incident_id = %s
        ORDER BY created_at DESC, history_id DESC
        LIMIT 100
        """,
        (incident_id,),
    )

    counts = _fetch_rows(
        """
        SELECT
            (
                SELECT COUNT(*)
                FROM public.incident_alerts
                WHERE incident_id = %s
            ) AS alert_count,
            (
                SELECT COUNT(*)
                FROM public.incident_history
                WHERE incident_id = %s
            ) AS history_count
        """,
        (incident_id, incident_id),
    )[0]

    return {
        **incident,
        "alert_count": counts["alert_count"],
        "history_count": counts["history_count"],
        "alerts": alerts,
        "history": history,
    }


def get_dashboard_summary():
    rows = _fetch_rows(
        """
        SELECT
            NOW() AS generated_at,

            (
                SELECT COUNT(*)
                FROM public.security_events
            ) AS total_events,

            (
                SELECT COUNT(*)
                FROM public.security_events
                WHERE event_time >= NOW() - INTERVAL '24 hours'
                  AND event_time <= NOW()
            ) AS events_last_24h,

            (
                SELECT COUNT(*)
                FROM public.security_alerts
            ) AS total_alerts,

            (
                SELECT COUNT(*)
                FROM public.security_alerts
                WHERE status = 'open'
            ) AS open_alerts,

            (
                SELECT COUNT(*)
                FROM public.incidents
            ) AS total_incidents,

            (
                SELECT COUNT(*)
                FROM public.incidents
                WHERE status = 'open'
            ) AS open_incidents,

            (
                SELECT COUNT(*)
                FROM public.registered_devices
            ) AS registered_devices,

            (
                SELECT COUNT(*)
                FROM public.registered_devices
                WHERE status = 'active'
            ) AS active_registrations,

            (
                SELECT COUNT(*)
                FROM public.registered_devices
                WHERE status = 'pending'
            ) AS pending_registrations,

            (
                SELECT COUNT(*)
                FROM public.registered_devices
                WHERE status = 'revoked'
            ) AS revoked_registrations,

            (
                SELECT COUNT(*)
                FROM public.security_alerts
                WHERE severity = 'high'
            ) AS high_severity_alerts,

            (
                SELECT COUNT(*)
                FROM public.alert_risk_assessments
                WHERE classification = 'normal'
            ) AS normal_risk,

            (
                SELECT COUNT(*)
                FROM public.alert_risk_assessments
                WHERE classification = 'suspicious'
            ) AS suspicious_risk,

            (
                SELECT COUNT(*)
                FROM public.alert_risk_assessments
                WHERE classification = 'malicious'
            ) AS malicious_risk,

            (
                SELECT COUNT(*)
                FROM public.security_alerts a
                WHERE NOT EXISTS (
                    SELECT 1
                    FROM public.alert_risk_assessments r
                    WHERE r.alert_id = a.alert_id
                )
            ) AS unassessed_alerts
        """,
        (),
    )

    return rows[0]


def list_devices(
    *,
    limit=50,
    offset=0,
    hostname=None,
    platform=None,
    status=None,
    criticality=None,
):
    _validate_pagination(limit, offset)

    return _fetch_rows(
        """
        SELECT
            device_id,
            hostname,
            platform,
            status,
            criticality,
            created_at,
            last_seen_at
        FROM public.registered_devices
        WHERE (%s::text IS NULL OR hostname = %s)
          AND (%s::text IS NULL OR platform = %s)
          AND (%s::text IS NULL OR status = %s)
          AND (%s::text IS NULL OR criticality = %s)
        ORDER BY
            last_seen_at DESC NULLS LAST,
            created_at DESC,
            device_id DESC
        LIMIT %s OFFSET %s
        """,
        (
            hostname, hostname,
            platform, platform,
            status, status,
            criticality, criticality,
            limit, offset,
        ),
    )


def get_device_detail(*, device_id):
    rows = _fetch_rows(
        """
        SELECT
            d.device_id,
            d.hostname,
            d.platform,
            d.status,
            d.criticality,
            d.created_at,
            d.last_seen_at,

            (
                SELECT COUNT(*)
                FROM public.security_events e
                WHERE e.device_id = d.device_id
            ) AS event_count,

            (
                SELECT COUNT(*)
                FROM public.security_alerts a
                WHERE a.device_id = d.device_id
            ) AS alert_count,

            (
                SELECT COUNT(*)
                FROM public.incidents i
                WHERE i.device_id = d.device_id
            ) AS incident_count

        FROM public.registered_devices d
        WHERE d.device_id = %s
        """,
        (device_id,),
    )

    return rows[0] if rows else None
