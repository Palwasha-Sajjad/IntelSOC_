"""Read-only IntelSOC LAnoBERT v0.2 CPU smoke test.

Run from IntelSOC repository root with .venv-lanobert Python. No SQL writes,
network downloads, or alert/risk effects. Log message contents are never printed.
"""
import os
from collections import Counter
from pathlib import Path
import sys

import psycopg
from dotenv import load_dotenv

from lanobert_v02.event_scoring_adapter import (
    ELIGIBLE_EVENTS,
    load_cpu_scorer,
    score_security_event,
)


def main():
    root = Path.cwd().resolve()
    if not (root / "backend" / "migrations").is_dir():
        raise RuntimeError("Run from the IntelSOC project root")
    load_dotenv(root / ".env", override=True)
    model_dir = Path.home() / "Downloads" / "IntelSOC-LAnoBERT-v0.2-model"
    scorer = load_cpu_scorer(model_dir)
    assert str(scorer.device) == "cpu"

    # Explicitly read-only transaction; no event or result writes.
    with psycopg.connect(
        host=os.getenv("POSTGRES_HOST", "127.0.0.1"),
        port=int(os.getenv("POSTGRES_PORT", "5433")),
        dbname=os.getenv("POSTGRES_DB", "intelsoc"),
        user=os.getenv("POSTGRES_USER", "intelsoc"),
        password=os.environ["POSTGRES_PASSWORD"],
        connect_timeout=5,
    ) as conn:
        with conn.cursor() as cur:
            cur.execute("SET TRANSACTION READ ONLY")
            cur.execute("""
                SELECT DISTINCT ON (source, event_type)
                    source, event_type, message
                FROM security_events
                WHERE source IN ('windows_eventlog', 'linux_journald', 'linux_audit')
                ORDER BY source, event_type, received_at DESC
            """)
            rows = cur.fetchall()

    counts = Counter()
    failed = False
    for source, event_type, message in rows:
        if event_type not in ELIGIBLE_EVENTS.get(source, ()):
            continue
        result = score_security_event(
            scorer, source=source, event_type=event_type,
            message=message, max_masks=16, batch_size=16,
        )
        counts[source] += 1
        print(
            source, event_type,
            "status=" + result["status"],
            "windows=" + str(result.get("details", {}).get("windows", "-")),
            "positions=" + str(result.get("details", {}).get("positions_scored", "-")),
            "latency_ms=" + str(round(result["latency_ms"], 1)),
        )
        if result["status"] != "processed":
            failed = True
        if "message" in result or "risk_score" in result or "verdict" in result:
            raise AssertionError("Adapter leaked a forbidden field")

    if not counts["windows_eventlog"] or not (counts["linux_journald"] or counts["linux_audit"]):
        raise RuntimeError("No live Windows/Linux events sampled: cannot verify both platforms")
    if failed:
        raise RuntimeError("At least one real CPU inference failed")
    print("PASS: real checkpoint on CPU; live Windows and Linux event formats; read-only DB")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Avoid printing raw log, credentials or model tracebacks by default.
        print("CHECK FAILED:", type(error).__name__)
        sys.exit(1)
