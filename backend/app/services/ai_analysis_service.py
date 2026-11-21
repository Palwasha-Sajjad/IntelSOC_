"""Read-only retrieval of LAnoBERT advisory analysis for authorized API views.

No writes, severity decisions, thresholds or raw event messages.
"""
from pathlib import Path

import psycopg
from dotenv import load_dotenv

from app.core.config import get_postgres_config

load_dotenv(Path(__file__).resolve().parents[3] / ".env")


_READ_SQL = """
    SELECT a.event_id, a.model_version, a.status,
           a.anomaly_score, a.latency_ms, a.processed_at,
           e.hostname, e.source, e.event_type
    FROM event_ai_analysis AS a
    JOIN security_events AS e ON e.event_id = a.event_id
    WHERE a.model_version = %s
    ORDER BY a.updated_at DESC, a.event_id DESC
    LIMIT %s
"""


def list_ai_analysis(*, model_version: str = "LAnoBERT-v0.2", limit: int = 20) -> list[dict]:
    """Return a bounded, newest-first view; no event messages or exception details."""
    if not 1 <= limit <= 50 or isinstance(limit, bool):
        raise ValueError("limit must be 1 through 50")
    if model_version != "LAnoBERT-v0.2":
        raise ValueError("unsupported model version")

    with psycopg.connect(**get_postgres_config(), connect_timeout=5) as conn:
        with conn.cursor() as cur:
            cur.execute("SET TRANSACTION READ ONLY")
            cur.execute(_READ_SQL, (model_version, limit))
            rows = cur.fetchall()

    return [
        {
            "event_id": row[0], "model_version": row[1], "status": row[2],
            "anomaly_score": row[3], "latency_ms": row[4],
            "processed_at": row[5], "hostname": row[6],
            "source": row[7], "event_type": row[8],
        }
        for row in rows
    ]


_SUMMARY_SQL = """
    SELECT COUNT(*)::bigint,
           COUNT(*) FILTER (WHERE status = 'processed')::bigint,
           COUNT(*) FILTER (WHERE status = 'failed')::bigint,
           COUNT(*) FILTER (WHERE status = 'skipped')::bigint,
           AVG(latency_ms) FILTER (WHERE status = 'processed'),
           MAX(processed_at) FILTER (WHERE status = 'processed')
    FROM event_ai_analysis
    WHERE model_version = %s
"""


def summarize_ai_analysis(*, model_version: str = "LAnoBERT-v0.2") -> dict:
    """Read one model-specific aggregate without reading event messages or scores.

    Latency reflects successful processed records only; no calibrated
    thresholds, severity or threat percentages are calculated.
    """
    if model_version != "LAnoBERT-v0.2":
        raise ValueError("unsupported model version")

    with psycopg.connect(**get_postgres_config(), connect_timeout=5) as conn:
        with conn.cursor() as cur:
            cur.execute("SET TRANSACTION READ ONLY")
            cur.execute(_SUMMARY_SQL, (model_version,))
            row = cur.fetchone()

    return {
        "model_version": model_version,
        "total": row[0],
        "processed": row[1],
        "failed": row[2],
        "skipped": row[3],
        "average_latency_ms": row[4],
        "last_processed_at": row[5],
    }
