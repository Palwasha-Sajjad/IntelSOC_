import json
import time
from datetime import timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import psycopg
from dotenv import load_dotenv

from app.analysis.failed_login_rule import (
    RULE_ID,
    DEFAULT_WINDOW,
    evaluate_repeated_failed_logins,
)
from app.analysis.failed_then_success_rule import (
    RULE_ID as AUTH_CORRELATION_RULE_ID,
    WINDOW as AUTH_CORRELATION_WINDOW,
    correlate_failed_then_successful_logins,
)
from app.analysis.explicit_credentials_rule import (
    RULE_ID as EXPLICIT_CREDENTIAL_RULE_ID,
    detect_unusual_explicit_credentials,
)
from app.analysis.script_block_rule import (
    RULE_ID as SCRIPT_BLOCK_RULE_ID,
    detect_suspicious_script_block,
    is_complete_script_block,
)
from app.analysis.process_creation_rule import (
    RULE_ID as PROCESS_CREATION_RULE_ID,
    detect_suspicious_process_creation,
)
from app.analysis.scheduled_task_rule import (
    RULE_ID as SCHEDULED_TASK_RULE_ID,
    detect_suspicious_scheduled_task,
)
from app.analysis.rule_dispatcher import RuleRunner, run_registered_rules
from app.analysis.account_lockout_rule import (
    RULE_ID as ACCOUNT_LOCKOUT_RULE_ID,
    detect_account_lockout,
)
from app.analysis.password_change_rule import (
    RULE_ID as PASSWORD_CHANGE_RULE_ID,
    detect_password_change_attempt,
)
from app.analysis.account_disable_delete_rule import (
    RULE_ID as ACCOUNT_DISABLE_DELETE_RULE_ID,
    detect_account_disable_or_delete,
)
from app.analysis.account_lifecycle_rule import (
    RULE_ID as ACCOUNT_LIFECYCLE_RULE_ID,
    detect_account_lifecycle,
)
from app.analysis.privileged_group_rule import (
    RULE_ID as PRIVILEGED_GROUP_RULE_ID,
    detect_privileged_group_member_added,
)
from app.analysis.security_log_cleared_rule import (
    RULE_ID as SECURITY_LOG_CLEARED_RULE_ID,
    detect_security_log_cleared,
)
from app.analysis.linux_ssh_bruteforce_rule import (
    RULE_ID as LINUX_SSH_BRUTEFORCE_RULE_ID,
    DEFAULT_WINDOW as LINUX_SSH_BRUTEFORCE_WINDOW,
    evaluate_ssh_bruteforce,
)
from app.analysis.linux_ssh_failed_success_rule import (
    RULE_ID as LINUX_SSH_AUTH_CORRELATION_RULE_ID,
    WINDOW as LINUX_SSH_AUTH_CORRELATION_WINDOW,
    correlate_ssh_failed_then_success,
)
from app.core.config import get_postgres_config
from app.services.alert_service import (
    create_alert_for_detection,
)
from app.services.detection_service import (
    mark_event_analysis_failed,
    mark_event_analysis_processed,
    persist_detection,
)
from app.services.incident_service import (
    correlate_alert_to_incident,
)
from app.services.windows_src_ip_service import (
    enrich_pending_windows_4625_ips,
)


ROOT = Path(__file__).resolve().parents[3]
load_dotenv(ROOT / ".env")

POLL_SECONDS = 1.0
BATCH_SIZE = 100


def fetch_unprocessed_failed_login_events(
    *,
    limit: int = BATCH_SIZE,
) -> list[dict[str, Any]]:
    """
    Return Windows EventID 4625 rows that have not been processed yet.

    Provider/channel validation remains the extractor's responsibility.
    Failed rows are eligible for retry; successfully processed rows are not.
    """

    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    e.event_id,
                    e.device_id,
                    e.event_time,
                    e.raw_event
                FROM security_events AS e
                LEFT JOIN event_rule_analysis_state AS s
                  ON s.event_id = e.event_id AND s.rule_id = %s
                WHERE e.source = 'windows_eventlog'
                  AND e.raw_event->>'EventID' = '4625'
                  AND (
                        s.event_id IS NULL
                        OR s.status = 'failed'
                  )
                ORDER BY e.event_time ASC, e.event_id ASC
                LIMIT %s
                """,
                (RULE_ID, limit),
            )

            rows = cursor.fetchall()

    return [
        {
            "event_id": str(event_id),
            "device_id": (
                str(device_id)
                if device_id is not None
                else ""
            ),
            "event_time": event_time,
            "raw_event": raw_event,
        }
        for event_id, device_id, event_time, raw_event in rows
    ]


def fetch_failed_login_history(
    *,
    start_time,
    end_time,
) -> list[dict[str, Any]]:
    """
    Return the bounded 4625 history needed for rolling-window evaluation.

    This includes already-processed evidence so a later polling cycle can
    understand whether the threshold was already crossed.
    """

    lookback_start = start_time - DEFAULT_WINDOW

    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    event_id,
                    device_id,
                    event_time,
                    raw_event
                FROM security_events
                WHERE source = 'windows_eventlog'
                  AND raw_event->>'EventID' = '4625'
                  AND event_time >= %s
                  AND event_time <= %s
                ORDER BY event_time ASC, event_id ASC
                """,
                (
                    lookback_start,
                    end_time,
                ),
            )

            rows = cursor.fetchall()

    return [
        {
            "event_id": str(event_id),
            "device_id": (
                str(device_id)
                if device_id is not None
                else ""
            ),
            "event_time": event_time,
            "raw_event": raw_event,
        }
        for event_id, device_id, event_time, raw_event in rows
    ]


def analyze_once(
    *,
    limit: int = BATCH_SIZE,
) -> dict[str, int]:
    """
    Analyze one bounded batch of stored Windows failed-login candidates.

    Detections are persisted only when their threshold-crossing event belongs
    to the current unprocessed batch. Historical lookback is context only.
    Each persisted detection maps to one alert, and each alert is then
    correlated into one incident before source events are marked processed.
    """

    pending = fetch_unprocessed_failed_login_events(
        limit=limit,
    )

    if not pending:
        return {
            "events_processed": 0,
            "detections_created": 0,
            "detections_reused": 0,
            "alerts_created": 0,
            "alerts_reused": 0,
            "incidents_created": 0,
            "incidents_reused": 0,
            "events_failed": 0,
        }

    batch_event_ids = {
        event["event_id"]
        for event in pending
    }

    start_time = min(
        event["event_time"]
        for event in pending
    )
    end_time = max(
        event["event_time"]
        for event in pending
    )

    try:
        history = fetch_failed_login_history(
            start_time=start_time,
            end_time=end_time,
        )

        candidates = evaluate_repeated_failed_logins(
            history
        )

        detections_created = 0
        detections_reused = 0
        alerts_created = 0
        alerts_reused = 0
        incidents_created = 0
        incidents_reused = 0

        for candidate in candidates:
            if (
                not candidate.event_ids
                or candidate.event_ids[-1]
                not in batch_event_ids
            ):
                continue

            detection = persist_detection(candidate)

            if detection.created:
                detections_created += 1
            else:
                detections_reused += 1

            alert = create_alert_for_detection(
                detection.detection_id
            )

            if alert.created:
                alerts_created += 1
            else:
                alerts_reused += 1

            incident = correlate_alert_to_incident(
                alert.alert_id
            )

            if incident.created:
                incidents_created += 1
            else:
                incidents_reused += 1

        for event in pending:
            mark_event_analysis_processed(
                UUID(event["event_id"])
            )

        # Optional metadata enrichment follows successful rule/alert/incident
        # persistence. It must never cause a completed detection to fail
        # or produce duplicate alerts on retry.
        try:
            enrich_pending_windows_4625_ips(pending)
        except Exception as error:
            print(
                f"Source IP enrichment failed (non-blocking): {error}",
                flush=True,
            )

        return {
            "events_processed": len(pending),
            "detections_created": detections_created,
            "detections_reused": detections_reused,
            "alerts_created": alerts_created,
            "alerts_reused": alerts_reused,
            "incidents_created": incidents_created,
            "incidents_reused": incidents_reused,
            "events_failed": 0,
        }

    except Exception as error:
        for event in pending:
            try:
                mark_event_analysis_failed(
                    UUID(event["event_id"]),
                    str(error),
                )
            except Exception:
                pass

        raise



def fetch_unprocessed_linux_ssh_failures(
    *, limit: int = BATCH_SIZE,
) -> list[dict[str, Any]]:
    """Return Linux SSH events not yet processed by LIN-001."""

    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    e.event_id,
                    e.device_id,
                    e.event_time,
                    e.src_ip,
                    e.message,
                    e.raw_event
                FROM security_events AS e
                LEFT JOIN event_rule_analysis_state AS s
                  ON s.event_id = e.event_id
                 AND s.rule_id = %s
                WHERE e.source = 'linux_journald'
                  AND e.event_type = 'linux_ssh_event'
                  AND e.device_id IS NOT NULL
                  AND e.src_ip IS NOT NULL
                  AND (s.event_id IS NULL OR s.status = 'failed')
                ORDER BY e.event_time ASC, e.event_id ASC
                LIMIT %s
                """,
                (LINUX_SSH_BRUTEFORCE_RULE_ID, limit),
            )
            rows = cursor.fetchall()

    return [
        {
            "event_id": str(event_id),
            "device_id": str(device_id),
            "event_time": event_time,
            "src_ip": str(src_ip),
            "message": message,
            "raw_event": raw_event,
        }
        for event_id, device_id, event_time, src_ip, message, raw_event in rows
    ]


def fetch_linux_ssh_failure_history(
    *,
    start_time,
    end_time,
) -> list[dict[str, Any]]:
    """Return bounded SSH evidence needed for LIN-001 rolling evaluation."""

    lookback_start = start_time - LINUX_SSH_BRUTEFORCE_WINDOW

    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    event_id,
                    device_id,
                    event_time,
                    src_ip,
                    message,
                    raw_event
                FROM security_events
                WHERE source = 'linux_journald'
                  AND event_type = 'linux_ssh_event'
                  AND device_id IS NOT NULL
                  AND src_ip IS NOT NULL
                  AND event_time >= %s
                  AND event_time <= %s
                ORDER BY event_time ASC, event_id ASC
                """,
                (lookback_start, end_time),
            )
            rows = cursor.fetchall()

    return [
        {
            "event_id": str(event_id),
            "device_id": str(device_id),
            "event_time": event_time,
            "src_ip": str(src_ip),
            "message": message,
            "raw_event": raw_event,
        }
        for event_id, device_id, event_time, src_ip, message, raw_event in rows
    ]


def analyze_linux_ssh_bruteforce_once(
    *, limit: int = BATCH_SIZE,
) -> dict[str, int]:
    """Run LIN-001 with bounded history and per-rule replay protection."""

    pending = fetch_unprocessed_linux_ssh_failures(limit=limit)

    if not pending:
        return {
            "events_processed": 0,
            "detections_created": 0,
            "detections_reused": 0,
            "alerts_created": 0,
            "alerts_reused": 0,
            "incidents_created": 0,
            "incidents_reused": 0,
            "events_failed": 0,
        }

    batch_event_ids = {event["event_id"] for event in pending}
    start_time = min(event["event_time"] for event in pending)
    end_time = max(event["event_time"] for event in pending)

    try:
        history = fetch_linux_ssh_failure_history(
            start_time=start_time,
            end_time=end_time,
        )
        candidates = evaluate_ssh_bruteforce(history)

        result = {
            "events_processed": 0,
            "detections_created": 0,
            "detections_reused": 0,
            "alerts_created": 0,
            "alerts_reused": 0,
            "incidents_created": 0,
            "incidents_reused": 0,
            "events_failed": 0,
        }

        for candidate in candidates:
            if (
                not candidate.event_ids
                or candidate.event_ids[-1] not in batch_event_ids
            ):
                continue

            detection = persist_detection(candidate)
            result[
                "detections_created"
                if detection.created
                else "detections_reused"
            ] += 1

            alert = create_alert_for_detection(detection.detection_id)
            result[
                "alerts_created" if alert.created else "alerts_reused"
            ] += 1

            incident = correlate_alert_to_incident(alert.alert_id)
            result[
                "incidents_created"
                if incident.created
                else "incidents_reused"
            ] += 1

        for event in pending:
            mark_event_analysis_processed(
                UUID(event["event_id"]),
                LINUX_SSH_BRUTEFORCE_RULE_ID,
            )
            result["events_processed"] += 1

        return result

    except Exception as error:
        for event in pending:
            try:
                mark_event_analysis_failed(
                    UUID(event["event_id"]),
                    str(error),
                    LINUX_SSH_BRUTEFORCE_RULE_ID,
                )
            except Exception:
                pass
        raise


def fetch_unprocessed_linux_ssh_successes(
    *, limit: int = BATCH_SIZE,
) -> list[dict[str, Any]]:
    """Return accepted SSH events not yet processed by LIN-002."""

    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    e.event_id,
                    e.device_id,
                    e.event_time,
                    e.src_ip,
                    e.message,
                    e.raw_event
                FROM security_events AS e
                LEFT JOIN event_rule_analysis_state AS s
                  ON s.event_id = e.event_id
                 AND s.rule_id = %s
                WHERE e.source = 'linux_journald'
                  AND e.event_type = 'linux_ssh_event'
                  AND e.device_id IS NOT NULL
                  AND e.src_ip IS NOT NULL
                  AND e.message ILIKE 'Accepted %%'
                  AND (s.event_id IS NULL OR s.status = 'failed')
                ORDER BY e.event_time ASC, e.event_id ASC
                LIMIT %s
                """,
                (LINUX_SSH_AUTH_CORRELATION_RULE_ID, limit),
            )
            rows = cursor.fetchall()

    return [
        {
            "event_id": str(event_id),
            "device_id": str(device_id),
            "event_time": event_time,
            "src_ip": str(src_ip),
            "message": message,
            "raw_event": raw_event,
        }
        for event_id, device_id, event_time, src_ip, message, raw_event in rows
    ]


def fetch_linux_ssh_auth_history(
    *,
    start_time,
    end_time,
) -> list[dict[str, Any]]:
    """Return bounded SSH failure/success evidence for LIN-002."""

    lookback_start = start_time - LINUX_SSH_AUTH_CORRELATION_WINDOW

    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    event_id,
                    device_id,
                    event_time,
                    src_ip,
                    message,
                    raw_event
                FROM security_events
                WHERE source = 'linux_journald'
                  AND event_type = 'linux_ssh_event'
                  AND device_id IS NOT NULL
                  AND src_ip IS NOT NULL
                  AND event_time >= %s
                  AND event_time <= %s
                ORDER BY event_time ASC, event_id ASC
                """,
                (lookback_start, end_time),
            )
            rows = cursor.fetchall()

    return [
        {
            "event_id": str(event_id),
            "device_id": str(device_id),
            "event_time": event_time,
            "src_ip": str(src_ip),
            "message": message,
            "raw_event": raw_event,
        }
        for event_id, device_id, event_time, src_ip, message, raw_event in rows
    ]


def analyze_linux_ssh_auth_correlation_once(
    *, limit: int = BATCH_SIZE,
) -> dict[str, int]:
    """Run LIN-002 using accepted SSH events as correlation triggers."""

    pending = fetch_unprocessed_linux_ssh_successes(limit=limit)

    if not pending:
        return {
            "events_processed": 0,
            "detections_created": 0,
            "detections_reused": 0,
            "alerts_created": 0,
            "alerts_reused": 0,
            "incidents_created": 0,
            "incidents_reused": 0,
            "events_failed": 0,
        }

    pending_ids = {event["event_id"] for event in pending}
    start_time = min(event["event_time"] for event in pending)
    end_time = max(event["event_time"] for event in pending)

    try:
        history = fetch_linux_ssh_auth_history(
            start_time=start_time,
            end_time=end_time,
        )
        candidates = correlate_ssh_failed_then_success(history)

        result = {
            "events_processed": 0,
            "detections_created": 0,
            "detections_reused": 0,
            "alerts_created": 0,
            "alerts_reused": 0,
            "incidents_created": 0,
            "incidents_reused": 0,
            "events_failed": 0,
        }

        for candidate in candidates:
            if (
                not candidate.event_ids
                or candidate.event_ids[-1] not in pending_ids
            ):
                continue

            detection = persist_detection(candidate)
            result[
                "detections_created"
                if detection.created
                else "detections_reused"
            ] += 1

            alert = create_alert_for_detection(detection.detection_id)
            result[
                "alerts_created" if alert.created else "alerts_reused"
            ] += 1

            incident = correlate_alert_to_incident(alert.alert_id)
            result[
                "incidents_created"
                if incident.created
                else "incidents_reused"
            ] += 1

        for event in pending:
            mark_event_analysis_processed(
                UUID(event["event_id"]),
                LINUX_SSH_AUTH_CORRELATION_RULE_ID,
            )
            result["events_processed"] += 1

        return result

    except Exception as error:
        for event in pending:
            try:
                mark_event_analysis_failed(
                    UUID(event["event_id"]),
                    str(error),
                    LINUX_SSH_AUTH_CORRELATION_RULE_ID,
                )
            except Exception:
                pass
        raise


def fetch_unprocessed_security_log_clears(
    *, limit: int = BATCH_SIZE,
) -> list[dict[str, Any]]:
    """Fetch only registered-device, genuine-shaped Windows 1102 records."""
    with psycopg.connect(
        **get_postgres_config(), connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT e.event_id, e.device_id, e.event_time, e.raw_event
                FROM security_events AS e
                LEFT JOIN event_rule_analysis_state AS s
                  ON s.event_id = e.event_id AND s.rule_id = %s
                WHERE e.source = 'windows_eventlog'
                  AND e.event_type = 'windows_security_event'
                  AND e.device_id IS NOT NULL
                  AND e.raw_event->>'EventID' = '1102'
                  AND lower(e.raw_event->>'Channel') = 'security'
                  AND lower(e.raw_event->>'ProviderName') =
                      'microsoft-windows-eventlog'
                  AND (s.event_id IS NULL OR s.status = 'failed')
                ORDER BY e.event_time ASC, e.event_id ASC
                LIMIT %s
                """,
                (SECURITY_LOG_CLEARED_RULE_ID, limit),
            )
            rows = cursor.fetchall()
    return [
        {
            "event_id": str(event_id),
            "device_id": str(device_id),
            "event_time": event_time,
            "raw_event": raw_event,
        }
        for event_id, device_id, event_time, raw_event in rows
    ]


def analyze_security_log_clears_once(
    *, limit: int = BATCH_SIZE,
) -> dict[str, int]:
    """Persist and individually acknowledge 1102 detections.

    Failures affect only WIN-002 per-rule state, never WIN-001.
    """
    pending = fetch_unprocessed_security_log_clears(limit=limit)
    result = {
        "events_processed": 0,
        "detections_created": 0,
        "detections_reused": 0,
        "alerts_created": 0,
        "alerts_reused": 0,
        "incidents_created": 0,
        "incidents_reused": 0,
        "events_failed": 0,
    }
    for event in pending:
        event_id = UUID(event["event_id"])
        try:
            candidate = detect_security_log_cleared(event)
            if candidate is not None:
                detection = persist_detection(candidate)
                result[
                    "detections_created" if detection.created
                    else "detections_reused"
                ] += 1
                alert = create_alert_for_detection(detection.detection_id)
                result[
                    "alerts_created" if alert.created else "alerts_reused"
                ] += 1
                incident = correlate_alert_to_incident(alert.alert_id)
                result[
                    "incidents_created" if incident.created
                    else "incidents_reused"
                ] += 1

            mark_event_analysis_processed(
                event_id, SECURITY_LOG_CLEARED_RULE_ID,
            )
            result["events_processed"] += 1
        except Exception as error:
            result["events_failed"] += 1
            try:
                mark_event_analysis_failed(
                    event_id, str(error), SECURITY_LOG_CLEARED_RULE_ID,
                )
            except Exception as state_error:
                print(
                    f"WIN-002 state update failed: {state_error}",
                    flush=True,
                )
            print(f"WIN-002 event failed: {error}", flush=True)
    return result



def fetch_unprocessed_privileged_group_events(
    *, limit: int = BATCH_SIZE,
) -> list[dict[str, Any]]:
    """Fetch bounded 4732 events for the independent WIN-003 rule."""
    with psycopg.connect(
        **get_postgres_config(), connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT e.event_id, e.device_id, e.event_time, e.raw_event
                FROM security_events AS e
                LEFT JOIN event_rule_analysis_state AS s
                  ON s.event_id = e.event_id AND s.rule_id = %s
                WHERE e.source = 'windows_eventlog'
                  AND e.event_type = 'windows_security_event'
                  AND e.device_id IS NOT NULL
                  AND e.raw_event->>'EventID' = '4732'
                  AND lower(e.raw_event->>'Channel') = 'security'
                  AND lower(e.raw_event->>'ProviderName') =
                      'microsoft-windows-security-auditing'
                  AND (s.event_id IS NULL OR s.status = 'failed')
                ORDER BY e.event_time ASC, e.event_id ASC
                LIMIT %s
                """,
                (PRIVILEGED_GROUP_RULE_ID, limit),
            )
            rows = cursor.fetchall()
    return [
        {
            "event_id": str(event_id),
            "device_id": str(device_id),
            "event_time": event_time,
            "raw_event": raw_event,
        }
        for event_id, device_id, event_time, raw_event in rows
    ]


def analyze_privileged_group_once(
    *, limit: int = BATCH_SIZE,
) -> dict[str, int]:
    """Process each 4732 event independently, preserving WIN-001/002 state."""
    pending = fetch_unprocessed_privileged_group_events(limit=limit)
    result = {
        "events_processed": 0,
        "detections_created": 0,
        "detections_reused": 0,
        "alerts_created": 0,
        "alerts_reused": 0,
        "incidents_created": 0,
        "incidents_reused": 0,
        "events_failed": 0,
    }
    for event in pending:
        event_id = UUID(event["event_id"])
        try:
            candidate = detect_privileged_group_member_added(event)
            if candidate is not None:
                detection = persist_detection(candidate)
                result[
                    "detections_created" if detection.created
                    else "detections_reused"
                ] += 1
                alert = create_alert_for_detection(detection.detection_id)
                result[
                    "alerts_created" if alert.created else "alerts_reused"
                ] += 1
                incident = correlate_alert_to_incident(alert.alert_id)
                result[
                    "incidents_created" if incident.created
                    else "incidents_reused"
                ] += 1

            mark_event_analysis_processed(
                event_id, PRIVILEGED_GROUP_RULE_ID,
            )
            result["events_processed"] += 1
        except Exception as error:
            result["events_failed"] += 1
            try:
                mark_event_analysis_failed(
                    event_id, str(error), PRIVILEGED_GROUP_RULE_ID,
                )
            except Exception as state_error:
                print(
                    f"WIN-003 state update failed: {state_error}",
                    flush=True,
                )
            print(f"WIN-003 event failed: {error}", flush=True)
    return result



def fetch_unprocessed_account_lifecycle_events(
    *, limit: int = BATCH_SIZE,
) -> list[dict[str, Any]]:
    """Fetch Windows account creation/enablement for independent WIN-004."""
    with psycopg.connect(
        **get_postgres_config(), connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT e.event_id, e.device_id, e.event_time, e.raw_event
                FROM security_events AS e
                LEFT JOIN event_rule_analysis_state AS s
                  ON s.event_id = e.event_id AND s.rule_id = %s
                WHERE e.source = 'windows_eventlog'
                  AND e.event_type = 'windows_security_event'
                  AND e.device_id IS NOT NULL
                  AND e.raw_event->>'EventID' IN ('4720', '4722')
                  AND lower(e.raw_event->>'Channel') = 'security'
                  AND lower(e.raw_event->>'ProviderName') =
                      'microsoft-windows-security-auditing'
                  AND (s.event_id IS NULL OR s.status = 'failed')
                ORDER BY e.event_time ASC, e.event_id ASC
                LIMIT %s
                """,
                (ACCOUNT_LIFECYCLE_RULE_ID, limit),
            )
            rows = cursor.fetchall()
    return [
        {
            "event_id": str(event_id),
            "device_id": str(device_id),
            "event_time": event_time,
            "raw_event": raw_event,
        }
        for event_id, device_id, event_time, raw_event in rows
    ]


def analyze_account_lifecycle_once(
    *, limit: int = BATCH_SIZE,
) -> dict[str, int]:
    """Process each 4720/4722 event with existing idempotent persistence."""
    pending = fetch_unprocessed_account_lifecycle_events(limit=limit)
    result = {
        "events_processed": 0,
        "detections_created": 0,
        "detections_reused": 0,
        "alerts_created": 0,
        "alerts_reused": 0,
        "incidents_created": 0,
        "incidents_reused": 0,
        "events_failed": 0,
    }
    for event in pending:
        event_id = UUID(event["event_id"])
        try:
            candidate = detect_account_lifecycle(event)
            if candidate is not None:
                detection = persist_detection(candidate)
                result[
                    "detections_created" if detection.created
                    else "detections_reused"
                ] += 1
                alert = create_alert_for_detection(detection.detection_id)
                result[
                    "alerts_created" if alert.created
                    else "alerts_reused"
                ] += 1
                incident = correlate_alert_to_incident(alert.alert_id)
                result[
                    "incidents_created" if incident.created
                    else "incidents_reused"
                ] += 1

            mark_event_analysis_processed(event_id, ACCOUNT_LIFECYCLE_RULE_ID)
            result["events_processed"] += 1
        except Exception as error:
            result["events_failed"] += 1
            try:
                mark_event_analysis_failed(
                    event_id, str(error), ACCOUNT_LIFECYCLE_RULE_ID,
                )
            except Exception as state_error:
                print(f"WIN-004 state update failed: {state_error}", flush=True)
            print(f"WIN-004 event failed: {error}", flush=True)
    return result



def fetch_unprocessed_account_disable_delete_events(
    *, limit: int = BATCH_SIZE,
) -> list[dict[str, Any]]:
    """Fetch WIN-005 account disable/delete events independently."""
    with psycopg.connect(
        **get_postgres_config(), connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT e.event_id, e.device_id, e.event_time, e.raw_event
                FROM security_events AS e
                LEFT JOIN event_rule_analysis_state AS s
                  ON s.event_id = e.event_id AND s.rule_id = %s
                WHERE e.source = 'windows_eventlog'
                  AND e.event_type = 'windows_security_event'
                  AND e.device_id IS NOT NULL
                  AND e.raw_event->>'EventID' IN ('4725', '4726')
                  AND lower(e.raw_event->>'Channel') = 'security'
                  AND lower(e.raw_event->>'ProviderName') =
                      'microsoft-windows-security-auditing'
                  AND (s.event_id IS NULL OR s.status = 'failed')
                ORDER BY e.event_time ASC, e.event_id ASC
                LIMIT %s
                """,
                (ACCOUNT_DISABLE_DELETE_RULE_ID, limit),
            )
            rows = cursor.fetchall()
    return [
        {
            "event_id": str(event_id),
            "device_id": str(device_id),
            "event_time": event_time,
            "raw_event": raw_event,
        }
        for event_id, device_id, event_time, raw_event in rows
    ]


def analyze_account_disable_delete_once(
    *, limit: int = BATCH_SIZE,
) -> dict[str, int]:
    """Persist WIN-005 detections with per-rule state and retry support."""
    pending = fetch_unprocessed_account_disable_delete_events(limit=limit)
    result = {
        "events_processed": 0,
        "detections_created": 0,
        "detections_reused": 0,
        "alerts_created": 0,
        "alerts_reused": 0,
        "incidents_created": 0,
        "incidents_reused": 0,
        "events_failed": 0,
    }
    for event in pending:
        event_id = UUID(event["event_id"])
        try:
            candidate = detect_account_disable_or_delete(event)
            if candidate is not None:
                detection = persist_detection(candidate)
                result[
                    "detections_created" if detection.created
                    else "detections_reused"
                ] += 1
                alert = create_alert_for_detection(detection.detection_id)
                result[
                    "alerts_created" if alert.created
                    else "alerts_reused"
                ] += 1
                incident = correlate_alert_to_incident(alert.alert_id)
                result[
                    "incidents_created" if incident.created
                    else "incidents_reused"
                ] += 1
            mark_event_analysis_processed(
                event_id, ACCOUNT_DISABLE_DELETE_RULE_ID,
            )
            result["events_processed"] += 1
        except Exception as error:
            result["events_failed"] += 1
            try:
                mark_event_analysis_failed(
                    event_id, str(error), ACCOUNT_DISABLE_DELETE_RULE_ID,
                )
            except Exception as state_error:
                print(f"WIN-005 state update failed: {state_error}", flush=True)
            print(f"WIN-005 event failed: {error}", flush=True)
    return result



def fetch_unprocessed_account_lockout_events(
    *, limit: int = BATCH_SIZE,
) -> list[dict[str, Any]]:
    """Fetch unhandled Windows lockout events for WIN-006 only."""
    with psycopg.connect(
        **get_postgres_config(), connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT e.event_id, e.device_id, e.event_time, e.raw_event
                FROM security_events AS e
                LEFT JOIN event_rule_analysis_state AS s
                  ON s.event_id = e.event_id AND s.rule_id = %s
                WHERE e.source = 'windows_eventlog'
                  AND e.event_type = 'windows_security_event'
                  AND e.device_id IS NOT NULL
                  AND e.raw_event->>'EventID' = '4740'
                  AND lower(e.raw_event->>'Channel') = 'security'
                  AND lower(e.raw_event->>'ProviderName') =
                      'microsoft-windows-security-auditing'
                  AND (s.event_id IS NULL OR s.status = 'failed')
                ORDER BY e.event_time ASC, e.event_id ASC
                LIMIT %s
                """,
                (ACCOUNT_LOCKOUT_RULE_ID, limit),
            )
            rows = cursor.fetchall()
    return [
        {
            "event_id": str(event_id),
            "device_id": str(device_id),
            "event_time": event_time,
            "raw_event": raw_event,
        }
        for event_id, device_id, event_time, raw_event in rows
    ]


def analyze_account_lockout_once(
    *, limit: int = BATCH_SIZE,
) -> dict[str, int]:
    """Detect and persist account lockouts using the existing alert pipeline."""
    pending = fetch_unprocessed_account_lockout_events(limit=limit)
    result = {
        "events_processed": 0,
        "detections_created": 0,
        "detections_reused": 0,
        "alerts_created": 0,
        "alerts_reused": 0,
        "incidents_created": 0,
        "incidents_reused": 0,
        "events_failed": 0,
    }
    for event in pending:
        event_id = UUID(event["event_id"])
        try:
            candidate = detect_account_lockout(event)
            if candidate is not None:
                detection = persist_detection(candidate)
                result[
                    "detections_created" if detection.created
                    else "detections_reused"
                ] += 1
                alert = create_alert_for_detection(detection.detection_id)
                result[
                    "alerts_created" if alert.created
                    else "alerts_reused"
                ] += 1
                incident = correlate_alert_to_incident(alert.alert_id)
                result[
                    "incidents_created" if incident.created
                    else "incidents_reused"
                ] += 1
            mark_event_analysis_processed(event_id, ACCOUNT_LOCKOUT_RULE_ID)
            result["events_processed"] += 1
        except Exception as error:
            result["events_failed"] += 1
            try:
                mark_event_analysis_failed(
                    event_id, str(error), ACCOUNT_LOCKOUT_RULE_ID,
                )
            except Exception as state_error:
                print(f"WIN-006 state update failed: {state_error}", flush=True)
            print(f"WIN-006 event failed: {error}", flush=True)
    return result



def fetch_unprocessed_password_change_events(
    *, limit: int = BATCH_SIZE,
) -> list[dict[str, Any]]:
    """Fetch only genuine-shaped Windows Security 4723 records for WIN-007."""
    with psycopg.connect(
        **get_postgres_config(), connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT e.event_id, e.device_id, e.event_time, e.raw_event
                FROM security_events AS e
                LEFT JOIN event_rule_analysis_state AS s
                  ON s.event_id = e.event_id AND s.rule_id = %s
                WHERE e.source = 'windows_eventlog'
                  AND e.event_type = 'windows_security_event'
                  AND e.device_id IS NOT NULL
                  AND e.raw_event->>'EventID' = '4723'
                  AND lower(e.raw_event->>'Channel') = 'security'
                  AND lower(e.raw_event->>'ProviderName') =
                      'microsoft-windows-security-auditing'
                  AND (s.event_id IS NULL OR s.status = 'failed')
                ORDER BY e.event_time ASC, e.event_id ASC
                LIMIT %s
                """,
                (PASSWORD_CHANGE_RULE_ID, limit),
            )
            rows = cursor.fetchall()
    return [
        {
            "event_id": str(event_id),
            "device_id": str(device_id),
            "event_time": event_time,
            "raw_event": raw_event,
        }
        for event_id, device_id, event_time, raw_event in rows
    ]


def analyze_password_change_once(
    *, limit: int = BATCH_SIZE,
) -> dict[str, int]:
    """Persist WIN-007 attempts through existing detection/alert/incident flow."""
    pending = fetch_unprocessed_password_change_events(limit=limit)
    result = {
        "events_processed": 0,
        "detections_created": 0,
        "detections_reused": 0,
        "alerts_created": 0,
        "alerts_reused": 0,
        "incidents_created": 0,
        "incidents_reused": 0,
        "events_failed": 0,
    }
    for event in pending:
        event_id = UUID(event["event_id"])
        try:
            candidate = detect_password_change_attempt(event)
            if candidate is not None:
                detection = persist_detection(candidate)
                result[
                    "detections_created" if detection.created
                    else "detections_reused"
                ] += 1
                alert = create_alert_for_detection(detection.detection_id)
                result[
                    "alerts_created" if alert.created
                    else "alerts_reused"
                ] += 1
                incident = correlate_alert_to_incident(alert.alert_id)
                result[
                    "incidents_created" if incident.created
                    else "incidents_reused"
                ] += 1
            mark_event_analysis_processed(event_id, PASSWORD_CHANGE_RULE_ID)
            result["events_processed"] += 1
        except Exception as error:
            result["events_failed"] += 1
            try:
                mark_event_analysis_failed(
                    event_id, str(error), PASSWORD_CHANGE_RULE_ID,
                )
            except Exception as state_error:
                print(f"WIN-007 state update failed: {state_error}", flush=True)
            print(f"WIN-007 event failed: {error}", flush=True)
    return result




def fetch_unprocessed_auth_success_events(
    *, limit: int = BATCH_SIZE,
) -> list[dict[str, Any]]:
    """Select genuine-shaped successful Windows logons not yet analyzed by R2-D1.

    Only interactive and remote sign-ins are candidates. Service logons do not
    enter the rule's work queue; the detector still validates the full payload.
    """
    with psycopg.connect(
        **get_postgres_config(), connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT e.event_id, e.device_id, e.event_time, e.raw_event
                FROM security_events e
                LEFT JOIN event_rule_analysis_state s
                  ON s.event_id = e.event_id AND s.rule_id = %s
                WHERE e.source = 'windows_eventlog'
                  AND e.event_type = 'windows_security_event'
                  AND e.device_id IS NOT NULL
                  AND e.raw_event->>'EventID' = '4624'
                  AND lower(e.raw_event->>'Channel') = 'security'
                  AND lower(e.raw_event->>'ProviderName') =
                      'microsoft-windows-security-auditing'
                  AND jsonb_typeof(e.raw_event->'StringInserts') = 'array'
                  AND (e.raw_event->'StringInserts'->>8) IN ('2','3','10','11')
                  AND (s.event_id IS NULL OR s.status = 'failed')
                ORDER BY e.event_time ASC, e.event_id ASC
                LIMIT %s
                """,
                (AUTH_CORRELATION_RULE_ID, limit),
            )
            rows = cursor.fetchall()
    return [
        {
            "event_id": str(event_id),
            "device_id": str(device_id),
            "event_time": event_time,
            "raw_event": raw_event,
        }
        for event_id, device_id, event_time, raw_event in rows
    ]


def fetch_auth_correlation_context(
    success_event: dict[str, Any],
) -> list[dict[str, Any]]:
    """Read earlier failures and all preceding successes, including same-time peers.

    When Windows records multiple 4624s at identical timestamps, order
    success triggers by stored UUID so only the first can consume a burst.
    Same-time failures are never treated as earlier failures.
    """
    with psycopg.connect(
        **get_postgres_config(), connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT event_id, device_id, event_time, raw_event
                FROM security_events
                WHERE source = 'windows_eventlog'
                  AND event_type = 'windows_security_event'
                  AND device_id = %s
                  AND raw_event->>'EventID' IN ('4625','4624')
                  AND lower(raw_event->>'Channel') = 'security'
                  AND lower(raw_event->>'ProviderName') =
                      'microsoft-windows-security-auditing'
                  AND event_time >= %s
                  AND (
                        event_time < %s
                        OR (
                            event_time = %s
                            AND raw_event->>'EventID' = '4624'
                            AND event_id < %s
                        )
                  )
                ORDER BY event_time ASC, event_id ASC
                """,
                (
                    success_event["device_id"],
                    success_event["event_time"] - AUTH_CORRELATION_WINDOW,
                    success_event["event_time"],
                    success_event["event_time"],
                    UUID(success_event["event_id"]),
                ),
            )
            rows = cursor.fetchall()
    return [
        {
            "event_id": str(event_id),
            "device_id": str(device_id),
            "event_time": event_time,
            "raw_event": raw_event,
        }
        for event_id, device_id, event_time, raw_event in rows
    ]


def analyze_auth_correlation_once(
    *, limit: int = BATCH_SIZE,
) -> dict[str, int]:
    """Independently process 4624 triggers and link the original 4625 evidence.

    State is acknowledged only after detection, alert and incident persistence.
    Replays/retries reuse existing fingerprints and alert/incident links.
    """
    pending = fetch_unprocessed_auth_success_events(limit=limit)
    result = {
        "events_processed": 0,
        "detections_created": 0,
        "detections_reused": 0,
        "alerts_created": 0,
        "alerts_reused": 0,
        "incidents_created": 0,
        "incidents_reused": 0,
        "events_failed": 0,
    }
    for success in pending:
        event_id = UUID(success["event_id"])
        try:
            history = fetch_auth_correlation_context(success)
            candidates = correlate_failed_then_successful_logins(
                [*history, success]
            )
            for candidate in candidates:
                if candidate.event_ids[-1] != success["event_id"]:
                    continue
                detection = persist_detection(candidate)
                result[
                    "detections_created" if detection.created
                    else "detections_reused"
                ] += 1
                alert = create_alert_for_detection(detection.detection_id)
                result[
                    "alerts_created" if alert.created
                    else "alerts_reused"
                ] += 1
                incident = correlate_alert_to_incident(alert.alert_id)
                result[
                    "incidents_created" if incident.created
                    else "incidents_reused"
                ] += 1
            mark_event_analysis_processed(
                event_id, AUTH_CORRELATION_RULE_ID,
            )
            result["events_processed"] += 1
        except Exception as error:
            result["events_failed"] += 1
            try:
                mark_event_analysis_failed(
                    event_id, str(error), AUTH_CORRELATION_RULE_ID,
                )
            except Exception as state_error:
                print(
                    f"WIN-008 analysis state failed: {state_error}",
                    flush=True,
                )
            print(f"WIN-008 correlation failed: {error}", flush=True)
    return result



def fetch_unprocessed_scheduled_task_events(
    *, limit: int = BATCH_SIZE,
) -> list[dict[str, Any]]:
    """Read genuine-shaped 4698/4702; state belongs only to WIN-009."""
    with psycopg.connect(
        **get_postgres_config(), connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT e.event_id, e.device_id, e.event_time, e.raw_event
                FROM security_events AS e
                LEFT JOIN event_rule_analysis_state AS s
                  ON s.event_id = e.event_id AND s.rule_id = %s
                WHERE e.source = 'windows_eventlog'
                  AND e.event_type = 'windows_security_event'
                  AND e.device_id IS NOT NULL
                  AND e.raw_event->>'EventID' IN ('4698','4702')
                  AND lower(e.raw_event->>'Channel') = 'security'
                  AND lower(e.raw_event->>'ProviderName') =
                      'microsoft-windows-security-auditing'
                  AND (s.event_id IS NULL OR s.status = 'failed')
                ORDER BY e.event_time ASC, e.event_id ASC
                LIMIT %s
                """,
                (SCHEDULED_TASK_RULE_ID, limit),
            )
            rows = cursor.fetchall()
    return [
        {
            "event_id": str(event_id),
            "device_id": str(device_id),
            "event_time": event_time,
            "raw_event": raw_event,
        }
        for event_id, device_id, event_time, raw_event in rows
    ]


def analyze_scheduled_tasks_once(
    *, limit: int = BATCH_SIZE,
) -> dict[str, int]:
    """Reuse existing idempotent detection/alert/incident services."""
    pending = fetch_unprocessed_scheduled_task_events(limit=limit)
    result = {
        "events_processed": 0,
        "detections_created": 0,
        "detections_reused": 0,
        "alerts_created": 0,
        "alerts_reused": 0,
        "incidents_created": 0,
        "incidents_reused": 0,
        "events_failed": 0,
    }
    for event in pending:
        event_id = UUID(event["event_id"])
        try:
            candidate = detect_suspicious_scheduled_task(event)
            if candidate is not None:
                detection = persist_detection(candidate)
                result[
                    "detections_created" if detection.created
                    else "detections_reused"
                ] += 1
                alert = create_alert_for_detection(detection.detection_id)
                result[
                    "alerts_created" if alert.created
                    else "alerts_reused"
                ] += 1
                incident = correlate_alert_to_incident(alert.alert_id)
                result[
                    "incidents_created" if incident.created
                    else "incidents_reused"
                ] += 1
            mark_event_analysis_processed(
                event_id, SCHEDULED_TASK_RULE_ID,
            )
            result["events_processed"] += 1
        except Exception as error:
            result["events_failed"] += 1
            try:
                mark_event_analysis_failed(
                    event_id, str(error), SCHEDULED_TASK_RULE_ID,
                )
            except Exception as state_error:
                print(
                    f"WIN-009 state update failed: {state_error}",
                    flush=True,
                )
            print(f"WIN-009 event failed: {error}", flush=True)
    return result




def fetch_unprocessed_process_creation_events(
    *, limit: int = BATCH_SIZE,
) -> list[dict[str, Any]]:
    """Fetch stored Windows 4688 evidence with independent WIN-010 state."""
    with psycopg.connect(
        **get_postgres_config(), connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT e.event_id, e.device_id, e.event_time, e.raw_event
                FROM security_events AS e
                LEFT JOIN event_rule_analysis_state AS s
                  ON s.event_id = e.event_id AND s.rule_id = %s
                WHERE e.source = 'windows_eventlog'
                  AND e.event_type = 'windows_security_event'
                  AND e.device_id IS NOT NULL
                  AND e.raw_event->>'EventID' = '4688'
                  AND lower(e.raw_event->>'Channel') = 'security'
                  AND lower(e.raw_event->>'ProviderName') =
                      'microsoft-windows-security-auditing'
                  AND (s.event_id IS NULL OR s.status = 'failed')
                ORDER BY e.event_time ASC, e.event_id ASC
                LIMIT %s
                """,
                (PROCESS_CREATION_RULE_ID, limit),
            )
            rows = cursor.fetchall()
    return [
        {
            "event_id": str(event_id),
            "device_id": str(device_id),
            "event_time": event_time,
            "raw_event": raw_event,
        }
        for event_id, device_id, event_time, raw_event in rows
    ]


def analyze_process_creations_once(
    *, limit: int = BATCH_SIZE,
) -> dict[str, int]:
    """Reuse existing alert and incident persistence, with per-rule retry."""
    pending = fetch_unprocessed_process_creation_events(limit=limit)
    result = {
        "events_processed": 0,
        "detections_created": 0,
        "detections_reused": 0,
        "alerts_created": 0,
        "alerts_reused": 0,
        "incidents_created": 0,
        "incidents_reused": 0,
        "events_failed": 0,
    }
    for event in pending:
        event_id = UUID(event["event_id"])
        try:
            candidate = detect_suspicious_process_creation(event)
            if candidate is not None:
                detection = persist_detection(candidate)
                result[
                    "detections_created" if detection.created
                    else "detections_reused"
                ] += 1
                alert = create_alert_for_detection(detection.detection_id)
                result[
                    "alerts_created" if alert.created
                    else "alerts_reused"
                ] += 1
                incident = correlate_alert_to_incident(alert.alert_id)
                result[
                    "incidents_created" if incident.created
                    else "incidents_reused"
                ] += 1
            mark_event_analysis_processed(
                event_id, PROCESS_CREATION_RULE_ID,
            )
            result["events_processed"] += 1
        except Exception as error:
            result["events_failed"] += 1
            try:
                mark_event_analysis_failed(
                    event_id, str(error), PROCESS_CREATION_RULE_ID,
                )
            except Exception as state_error:
                print(f"WIN-010 state update failed: {state_error}", flush=True)
            print(f"WIN-010 event failed: {error}", flush=True)
    return result

def fetch_pending_script_block_groups(
    *, limit: int = 25,
) -> list[list[dict[str, Any]]]:
    """Fetch whole script blocks (not LIMIT-ed fragments) for WIN-011.

    Select pending/failed block IDs, then retrieve *all* stored parts. This
    intentionally defers incomplete blocks; new fragments may arrive later.
    """
    with psycopg.connect(
        **get_postgres_config(), connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                WITH eligible AS (
                    SELECT e.event_id, e.device_id, e.event_time, e.raw_event,
                           e.raw_event->'StringInserts'->>3 AS block_id,
                           s.status
                    FROM security_events e
                    LEFT JOIN event_rule_analysis_state s
                      ON s.event_id=e.event_id AND s.rule_id=%s
                    WHERE e.source='windows_eventlog'
                      AND e.event_type =
                        'windows_microsoft-windows-powershell/operational_event'
                      AND e.device_id IS NOT NULL
                      AND e.raw_event->>'EventID'='4104'
                      AND lower(e.raw_event->>'Channel') =
                        'microsoft-windows-powershell/operational'
                      AND lower(e.raw_event->>'ProviderName') =
                        'microsoft-windows-powershell'
                      AND jsonb_typeof(e.raw_event->'StringInserts')='array'
                      AND jsonb_array_length(e.raw_event->'StringInserts')=5
                ),
                chosen AS (
                    SELECT device_id, block_id, MIN(event_time) AS first_seen
                    FROM eligible
                    WHERE block_id IS NOT NULL
                    GROUP BY device_id, block_id
                    HAVING BOOL_OR(status IS NULL OR status='failed')
                       AND BOOL_AND(
                           (raw_event->'StringInserts'->>0) ~ '^[0-9]+$'
                           AND (raw_event->'StringInserts'->>1) ~ '^[0-9]+$'
                       )
                       AND MIN(
                           CASE WHEN (raw_event->'StringInserts'->>1) ~ '^[0-9]+$'
                                THEN (raw_event->'StringInserts'->>1)::integer END
                       ) = MAX(
                           CASE WHEN (raw_event->'StringInserts'->>1) ~ '^[0-9]+$'
                                THEN (raw_event->'StringInserts'->>1)::integer END
                       )
                       AND COUNT(*) = MAX(
                           CASE WHEN (raw_event->'StringInserts'->>1) ~ '^[0-9]+$'
                                THEN (raw_event->'StringInserts'->>1)::integer END
                       )
                       AND COUNT(DISTINCT raw_event->'StringInserts'->>0) = COUNT(*)
                    ORDER BY first_seen, device_id, block_id
                    LIMIT %s
                )
                SELECT e.event_id, e.device_id, e.event_time, e.raw_event,
                       e.block_id
                FROM eligible e JOIN chosen c
                  ON e.device_id=c.device_id AND e.block_id=c.block_id
                ORDER BY e.device_id, e.block_id, e.event_time, e.event_id
                """,
                (SCRIPT_BLOCK_RULE_ID, limit),
            )
            rows = cursor.fetchall()
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for event_id, device_id, timestamp, raw, block_id in rows:
        key = (str(device_id), block_id.casefold())
        groups.setdefault(key, []).append({
            "event_id": str(event_id),
            "device_id": str(device_id),
            "event_time": timestamp,
            "raw_event": raw,
        })
    return list(groups.values())


def analyze_script_blocks_once(*, limit: int = 25) -> dict[str, int]:
    """Process complete 4104 blocks with original-event evidence links."""
    groups = fetch_pending_script_block_groups(limit=limit)
    result = {
        "events_processed": 0,
        "detections_created": 0,
        "detections_reused": 0,
        "alerts_created": 0,
        "alerts_reused": 0,
        "incidents_created": 0,
        "incidents_reused": 0,
        "events_failed": 0,
    }
    for group in groups:
        if not is_complete_script_block(group):
            # Never acknowledge a missing, duplicated, or inconsistent part.
            continue
        try:
            candidate = detect_suspicious_script_block(group)
            if candidate is not None:
                detection = persist_detection(candidate)
                result[
                    "detections_created" if detection.created
                    else "detections_reused"
                ] += 1
                alert = create_alert_for_detection(detection.detection_id)
                result[
                    "alerts_created" if alert.created
                    else "alerts_reused"
                ] += 1
                incident = correlate_alert_to_incident(alert.alert_id)
                result[
                    "incidents_created" if incident.created
                    else "incidents_reused"
                ] += 1
            for event in group:
                mark_event_analysis_processed(
                    UUID(event["event_id"]), SCRIPT_BLOCK_RULE_ID,
                )
                result["events_processed"] += 1
        except Exception as error:
            result["events_failed"] += 1
            for event in group:
                try:
                    mark_event_analysis_failed(
                        UUID(event["event_id"]), str(error),
                        SCRIPT_BLOCK_RULE_ID,
                    )
                except Exception as state_error:
                    print(
                        f"WIN-011 state update failed: {state_error}",
                        flush=True,
                    )
            print(f"WIN-011 block failed: {error}", flush=True)
    return result



def fetch_unprocessed_explicit_credential_events(
    *, limit: int = BATCH_SIZE,
) -> list[dict[str, Any]]:
    """Read authentic 4648 evidence, isolated by WIN-012 processing state."""
    with psycopg.connect(
        **get_postgres_config(), connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT e.event_id, e.device_id, e.event_time, e.raw_event
                FROM security_events e
                LEFT JOIN event_rule_analysis_state s
                  ON s.event_id = e.event_id AND s.rule_id = %s
                WHERE e.source = 'windows_eventlog'
                  AND e.event_type = 'windows_security_event'
                  AND e.device_id IS NOT NULL
                  AND e.raw_event->>'EventID' = '4648'
                  AND lower(e.raw_event->>'Channel') = 'security'
                  AND lower(e.raw_event->>'ProviderName') =
                      'microsoft-windows-security-auditing'
                  AND (s.event_id IS NULL OR s.status = 'failed')
                ORDER BY e.event_time ASC, e.event_id ASC
                LIMIT %s
                """,
                (EXPLICIT_CREDENTIAL_RULE_ID, limit),
            )
            rows = cursor.fetchall()
    return [
        {
            "event_id": str(event_id),
            "device_id": str(device_id),
            "event_time": timestamp,
            "raw_event": raw_event,
        }
        for event_id, device_id, timestamp, raw_event in rows
    ]


def analyze_explicit_credentials_once(
    *, limit: int = BATCH_SIZE,
) -> dict[str, int]:
    """Reuse existing idempotent detection, alert, incident services."""
    pending = fetch_unprocessed_explicit_credential_events(limit=limit)
    result = {
        "events_processed": 0,
        "detections_created": 0,
        "detections_reused": 0,
        "alerts_created": 0,
        "alerts_reused": 0,
        "incidents_created": 0,
        "incidents_reused": 0,
        "events_failed": 0,
    }
    for event in pending:
        event_id = UUID(event["event_id"])
        try:
            candidate = detect_unusual_explicit_credentials(event)
            if candidate is not None:
                detection = persist_detection(candidate)
                result[
                    "detections_created" if detection.created
                    else "detections_reused"
                ] += 1
                alert = create_alert_for_detection(detection.detection_id)
                result[
                    "alerts_created" if alert.created
                    else "alerts_reused"
                ] += 1
                incident = correlate_alert_to_incident(alert.alert_id)
                result[
                    "incidents_created" if incident.created
                    else "incidents_reused"
                ] += 1
            mark_event_analysis_processed(
                event_id, EXPLICIT_CREDENTIAL_RULE_ID,
            )
            result["events_processed"] += 1
        except Exception as error:
            result["events_failed"] += 1
            try:
                mark_event_analysis_failed(
                    event_id, str(error), EXPLICIT_CREDENTIAL_RULE_ID,
                )
            except Exception as state_error:
                print(f"WIN-012 state update failed: {state_error}", flush=True)
            print(f"WIN-012 event failed: {error}", flush=True)
    return result


def main() -> None:
    print(
        "IntelSOC analysis worker started",
        flush=True,
    )

    # New rules will register here with independent runners and state.
    rules = (
        RuleRunner(RULE_ID, analyze_once),
        RuleRunner(LINUX_SSH_BRUTEFORCE_RULE_ID, analyze_linux_ssh_bruteforce_once),
        RuleRunner(LINUX_SSH_AUTH_CORRELATION_RULE_ID, analyze_linux_ssh_auth_correlation_once),
        RuleRunner(SECURITY_LOG_CLEARED_RULE_ID, analyze_security_log_clears_once),
        RuleRunner(PRIVILEGED_GROUP_RULE_ID, analyze_privileged_group_once),
        RuleRunner(ACCOUNT_LIFECYCLE_RULE_ID, analyze_account_lifecycle_once),
        RuleRunner(ACCOUNT_DISABLE_DELETE_RULE_ID, analyze_account_disable_delete_once),
        RuleRunner(ACCOUNT_LOCKOUT_RULE_ID, analyze_account_lockout_once),
        RuleRunner(PASSWORD_CHANGE_RULE_ID, analyze_password_change_once),
        RuleRunner(AUTH_CORRELATION_RULE_ID, analyze_auth_correlation_once),
        RuleRunner(SCHEDULED_TASK_RULE_ID, analyze_scheduled_tasks_once),
        RuleRunner(PROCESS_CREATION_RULE_ID, analyze_process_creations_once),
        RuleRunner(SCRIPT_BLOCK_RULE_ID, analyze_script_blocks_once),
        RuleRunner(EXPLICIT_CREDENTIAL_RULE_ID, analyze_explicit_credentials_once),
    )

    while True:
        for outcome in run_registered_rules(rules):
            if outcome.error is not None:
                print(
                    f"Rule {outcome.rule_id} error: {outcome.error}",
                    flush=True,
                )
            elif outcome.result and (
                outcome.result["events_processed"] or outcome.result["events_failed"]
            ):
                print(
                    json.dumps({
                        "rule_id": outcome.rule_id,
                        **outcome.result,
                    }),
                    flush=True,
                )

        time.sleep(POLL_SECONDS)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAnalysis worker stopped")
