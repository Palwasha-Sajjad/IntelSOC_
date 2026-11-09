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
from app.analysis.rule_dispatcher import RuleRunner, run_registered_rules
from app.analysis.security_log_cleared_rule import (
    RULE_ID as SECURITY_LOG_CLEARED_RULE_ID,
    detect_security_log_cleared,
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


def main() -> None:
    print(
        "IntelSOC analysis worker started",
        flush=True,
    )

    # New rules will register here with independent runners and state.
    rules = (
        RuleRunner(RULE_ID, analyze_once),
        RuleRunner(SECURITY_LOG_CLEARED_RULE_ID, analyze_security_log_clears_once),
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
