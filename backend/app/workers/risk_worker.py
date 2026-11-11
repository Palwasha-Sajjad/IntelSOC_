import json
import time
from pathlib import Path
from uuid import UUID

import psycopg
from dotenv import load_dotenv

from app.core.config import get_postgres_config
from app.services.risk_scoring_service import assess_alert_risk


ROOT = Path(__file__).resolve().parents[3]
load_dotenv(ROOT / ".env", override=True)

POLL_SECONDS = 1.0
BATCH_SIZE = 50
RETRY_DELAY_SECONDS = 30
REQUIRED_TI_PROVIDERS = ("virustotal", "abuseipdb")


def validate_risk_schema() -> None:
    """Fail fast when the risk migration has not been applied."""
    required_tables = (
        "alert_ai_evidence",
        "alert_risk_assessments",
        "alert_risk_analysis_state",
    )

    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            for table in required_tables:
                cursor.execute(
                    "SELECT to_regclass(%s)",
                    (f"public.{table}",),
                )
                row = cursor.fetchone()
                if row is None or row[0] is None:
                    raise RuntimeError(
                        f"Risk scoring schema is missing table: {table}"
                    )


def fetch_pending_risk_alerts(
    *,
    limit: int = BATCH_SIZE,
    retry_delay_seconds: int = RETRY_DELAY_SECONDS,
) -> list[UUID]:
    """Return alerts whose source evidence is complete and whose score is stale.

    Both current TI providers must be processed. Failed TI enrichment is left
    for the TI worker to retry instead of being interpreted as benign.
    A future LAnoBERT row automatically makes an existing assessment stale.
    """

    if limit < 1:
        raise ValueError("limit must be positive")
    if retry_delay_seconds < 1:
        raise ValueError("retry_delay_seconds must be positive")

    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT a.alert_id
                FROM security_alerts AS a
                JOIN alert_ti_analysis_state AS vt
                  ON vt.alert_id = a.alert_id
                 AND vt.provider = 'virustotal'
                 AND vt.status = 'processed'
                JOIN alert_ti_analysis_state AS abuse
                  ON abuse.alert_id = a.alert_id
                 AND abuse.provider = 'abuseipdb'
                 AND abuse.status = 'processed'
                LEFT JOIN alert_risk_assessments AS ra
                  ON ra.alert_id = a.alert_id
                LEFT JOIN alert_ai_evidence AS ai
                  ON ai.alert_id = a.alert_id
                LEFT JOIN alert_risk_analysis_state AS rs
                  ON rs.alert_id = a.alert_id
                WHERE (
                    ra.alert_id IS NULL
                    OR (
                        ra.assessment_status = 'provisional'
                        AND ai.alert_id IS NOT NULL
                    )
                    OR ai.updated_at > ra.updated_at
                    OR EXISTS (
                        SELECT 1
                        FROM alert_ti_indicators AS ati
                        JOIN ti_results AS tr
                          ON tr.result_id = ati.result_id
                        WHERE ati.alert_id = a.alert_id
                          AND tr.updated_at > ra.updated_at
                    )
                    OR ra.score_version <> '1.1'
                )
                AND (
                    rs.alert_id IS NULL
                    OR rs.status = 'processed'
                    OR (
                        rs.status = 'failed'
                        AND rs.updated_at <= (
                            NOW() - (%s * INTERVAL '1 second')
                        )
                    )
                )
                ORDER BY a.created_at ASC, a.alert_id ASC
                LIMIT %s
                """,
                (retry_delay_seconds, limit),
            )
            rows = cursor.fetchall()

    return [UUID(str(row[0])) for row in rows]


def mark_risk_processed(alert_id: UUID | str) -> None:
    _upsert_risk_state(
        alert_id=alert_id,
        status="processed",
        error=None,
    )


def mark_risk_failed(alert_id: UUID | str, error: str) -> None:
    _upsert_risk_state(
        alert_id=alert_id,
        status="failed",
        error=str(error).strip()[:4000],
    )


def _upsert_risk_state(
    *,
    alert_id: UUID | str,
    status: str,
    error: str | None,
) -> None:
    alert_id = UUID(str(alert_id))
    if status not in {"processed", "failed"}:
        raise ValueError("unsupported risk analysis state")

    with psycopg.connect(
        **get_postgres_config(),
        connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO alert_risk_analysis_state (
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
                    attempts = alert_risk_analysis_state.attempts + 1,
                    last_error = EXCLUDED.last_error,
                    processed_at = CASE
                        WHEN EXCLUDED.status = 'processed' THEN NOW()
                        ELSE alert_risk_analysis_state.processed_at
                    END,
                    updated_at = NOW()
                """,
                (alert_id, status, error, status),
            )


def process_risk_batch(
    *,
    limit: int = BATCH_SIZE,
    retry_delay_seconds: int = RETRY_DELAY_SECONDS,
) -> dict[str, int]:
    alert_ids = fetch_pending_risk_alerts(
        limit=limit,
        retry_delay_seconds=retry_delay_seconds,
    )

    result = {
        "alerts_selected": len(alert_ids),
        "alerts_processed": 0,
        "alerts_failed": 0,
        "normal": 0,
        "suspicious": 0,
        "malicious": 0,
    }

    for alert_id in alert_ids:
        try:
            assessment = assess_alert_risk(alert_id)
            mark_risk_processed(alert_id)
            result["alerts_processed"] += 1
            result[assessment.classification] += 1

            print(
                json.dumps(
                    {
                        "alert_id": str(alert_id),
                        "risk_score": assessment.overall_score,
                        "classification": assessment.classification,
                        "rule_score": assessment.rule_score,
                        "ti_score": assessment.ti_score,
                        "lanobert_score": assessment.lanobert_score,
                    }
                ),
                flush=True,
            )

        except Exception as error:
            result["alerts_failed"] += 1
            try:
                mark_risk_failed(alert_id, str(error))
            except Exception as state_error:
                print(
                    f"Risk state update failed for {alert_id}: {state_error}",
                    flush=True,
                )

            print(
                f"Risk scoring failed for alert {alert_id}: {error}",
                flush=True,
            )

    return result


def main() -> None:
    validate_risk_schema()
    print("IntelSOC risk scoring worker started", flush=True)

    while True:
        try:
            result = process_risk_batch()
            if result["alerts_selected"]:
                print(
                    "Risk batch: "
                    f"selected={result['alerts_selected']} "
                    f"processed={result['alerts_processed']} "
                    f"failed={result['alerts_failed']} "
                    f"normal={result['normal']} "
                    f"suspicious={result['suspicious']} "
                    f"malicious={result['malicious']}",
                    flush=True,
                )

        except (psycopg.Error, OSError) as error:
            print(
                f"Risk worker database error: {error}",
                flush=True,
            )

        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nRisk scoring worker stopped", flush=True)
