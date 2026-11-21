"""Opt-in, bounded LAnoBERT v0.2 advisory analysis for stored IntelSOC events.

This worker is intentionally not a daemon and is not wired into Start-IntelSOC.
Use .venv-lanobert (Python 3.11); never use the backend's separate venv.
Requires migration 013. Its only write target is event_ai_analysis.
"""

import argparse
import os
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from dotenv import load_dotenv
import psycopg
from psycopg.types.json import Jsonb

from lanobert_v02.event_scoring_adapter import (
    ELIGIBLE_EVENTS,
    MODEL_VERSION,
    load_cpu_scorer,
    score_security_event,
)

MAX_BATCH = 20

# Explicitly restrict eligibility in SQL, rather than scanning or loading arbitrary events.
# Keeping these static also makes it evident which sources can reach the scorer.
_ELIGIBLE_SQL = " OR ".join(
    f"(e.source = %s AND e.event_type = ANY(%s))" for _ in ELIGIBLE_EVENTS
)
_SELECT_SQL = f"""
    SELECT e.event_id, e.source, e.event_type, e.message
    FROM security_events AS e
    WHERE e.received_at >= %s
      AND ({_ELIGIBLE_SQL})
      AND NOT EXISTS (
          SELECT 1 FROM event_ai_analysis AS a
          WHERE a.event_id = e.event_id AND a.model_version = %s
      )
    ORDER BY e.received_at ASC, e.event_id ASC
    LIMIT %s
"""

# No UPDATE and no references to alert, detection, incident, TI or risk tables.
_INSERT_SQL = """
    INSERT INTO event_ai_analysis (
        event_id, model_version, status, anomaly_score, latency_ms,
        attempts, last_error, details, processed_at, updated_at
    ) VALUES (
        %s, %s, %s, %s, %s, 1, %s, %s,
        CASE WHEN %s = 'processed' THEN NOW() ELSE NULL END, NOW()
    )
    ON CONFLICT (event_id, model_version) DO NOTHING
"""


def parse_since(value: str) -> datetime:
    """Require an explicit, timezone-aware start time; do not scan history by default."""
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError) as exc:
        raise ValueError("--since must be an ISO 8601 timestamp with timezone") from exc
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError("--since must include a timezone")
    if result > datetime.now(timezone.utc):
        raise ValueError("--since cannot be in the future")
    return result


def validate_limit(limit: int) -> None:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_BATCH:
        raise ValueError(f"limit must be between 1 and {MAX_BATCH}")


def database_config() -> dict:
    return {
        "host": os.getenv("POSTGRES_HOST", "127.0.0.1"),
        "port": int(os.getenv("POSTGRES_PORT", "5433")),
        "dbname": os.getenv("POSTGRES_DB", "intelsoc"),
        "user": os.getenv("POSTGRES_USER", "intelsoc"),
        "password": os.environ["POSTGRES_PASSWORD"],
        "connect_timeout": 5,
    }


def select_events(connect, since: datetime, limit: int):
    """Read candidate event messages; never load raw_event or secrets into output."""
    validate_limit(limit)
    params = [since]
    for source, types in ELIGIBLE_EVENTS.items():
        params.extend((source, sorted(types)))
    params.extend((MODEL_VERSION, limit))
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("SET TRANSACTION READ ONLY")
            cur.execute(_SELECT_SQL, params)
            return cur.fetchall()


def store_result(connect, event_id: UUID, result: dict) -> bool:
    """Single INSERT, never update or delete an existing AI result."""
    status = result["status"]
    if status not in ("processed", "failed", "skipped"):
        raise ValueError("unsupported scoring status")
    # Never save a raw exception or event message into failure fields.
    error_code = "inference_error" if status == "failed" else None
    details = result.get("details", {}) if status == "processed" else {}
    params = (
        event_id, MODEL_VERSION, status,
        result.get("anomaly_score") if status == "processed" else None,
        result.get("latency_ms"), error_code, Jsonb(details), status,
    )
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(_INSERT_SQL, params)
            return cur.rowcount == 1


def run_batch(*, since: datetime, limit: int, write_results: bool,
              model_dir: Path, connect=None, load_model=load_cpu_scorer,
              score_event=score_security_event) -> dict:
    """Process at most one bounded batch. Model loaded once per invocation.

    By default this is a dry run. It never inserts unless write_results=True.
    """
    validate_limit(limit)
    if since.tzinfo is None or since.utcoffset() is None:
        raise ValueError("since must be timezone-aware")
    if connect is None:
        connect = lambda: psycopg.connect(**database_config())

    events = select_events(connect, since, limit)
    counts = {"selected": len(events), "processed": 0, "failed": 0,
              "skipped": 0, "inserted": 0, "dry_run": not write_results}
    if not events:
        return counts

    scorer = load_model(model_dir)
    for event_id, source, event_type, message in events:
        try:
            result = score_event(scorer, source=source,
                                 event_type=event_type, message=message,
                                 max_masks=16, batch_size=16)
            status = result["status"]
        except Exception:
            # Input validation can raise before inference; keep worker isolated.
            result = {"status": "failed", "reason": "inference_error"}
            status = "failed"
        if status not in ("processed", "failed", "skipped"):
            result = {"status": "failed", "reason": "inference_error"}
            status = "failed"
        counts[status] += 1
        if write_results and store_result(connect, event_id, result):
            counts["inserted"] += 1
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--since", required=True,
                        help="ISO 8601 start time with offset, e.g. 2026-11-21T00:00:00+05:00")
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument("--model-dir", type=Path,
                        default=Path.home() / "Downloads" / "IntelSOC-LAnoBERT-v0.2-model")
    parser.add_argument("--write-results", action="store_true",
                        help="Explicitly enable INSERTs into event_ai_analysis")
    args = parser.parse_args()
    since = parse_since(args.since)
    validate_limit(args.limit)
    root = Path(__file__).resolve().parents[1]
    load_dotenv(root / ".env", override=True)
    result = run_batch(since=since, limit=args.limit,
                       write_results=args.write_results,
                       model_dir=args.model_dir)
    print("LAnoBERT advisory batch:", result)


if __name__ == "__main__":
    main()
