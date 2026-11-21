"""Opt-in monitoring loop for the existing LAnoBERT v0.2 advisory batch worker.

No changes to IntelSOC startup/shutdown scripts. No automatic monitoring.
Run manually using the LAnoBERT Python 3.11 virtual environment.

The runner reuses a single CPU model instance across bounded batches and
requires explicit confirmation before writing event_ai_analysis rows.
"""

import argparse
import time
from datetime import datetime
from pathlib import Path
from typing import Callable


MIN_POLL_SECONDS = 2.0
MAX_POLL_SECONDS = 300.0


def validate_monitor_options(*, since: datetime, limit: int, poll_seconds: float,
                             write_results: bool, max_cycles: int | None) -> None:
    """Fail before model/DB loading on unsafe runtime options."""
    from lanobert_v02.ai_batch_worker import validate_limit

    validate_limit(limit)
    if not isinstance(since, datetime) or since.tzinfo is None or since.utcoffset() is None:
        raise ValueError("since must be a timezone-aware datetime")
    if isinstance(poll_seconds, bool) or not isinstance(poll_seconds, (int, float)):
        raise ValueError("poll_seconds must be numeric")
    if not MIN_POLL_SECONDS <= poll_seconds <= MAX_POLL_SECONDS:
        raise ValueError("poll_seconds must be between 2 and 300 seconds")
    if not isinstance(write_results, bool) or not write_results:
        raise ValueError("continuous monitoring requires explicit --write-results")
    if max_cycles is not None and (
        isinstance(max_cycles, bool) or not isinstance(max_cycles, int) or max_cycles < 1
    ):
        raise ValueError("max_cycles must be a positive integer")


def monitor(*, since: datetime, limit: int, poll_seconds: float, model_dir: Path,
            write_results: bool, max_cycles: int | None = None,
            batch_fn: Callable | None = None, model_loader: Callable | None = None,
            sleep_fn: Callable[[float], None] = time.sleep,
            reporter: Callable[[str], None] = print) -> dict:
    """Run bounded batches; sleep even when backlogged to limit CPU pressure.

    The model is loaded lazily on the first nonempty batch, then reused.
    Unexpected DB/model errors stop the runner rather than silently retrying.
    KeyboardInterrupt propagates to main for a clean operator stop.
    """
    validate_monitor_options(
        since=since, limit=limit, poll_seconds=poll_seconds,
        write_results=write_results, max_cycles=max_cycles,
    )
    if batch_fn is None or model_loader is None:
        from lanobert_v02.ai_batch_worker import run_batch
        from lanobert_v02.event_scoring_adapter import load_cpu_scorer
        batch_fn = run_batch if batch_fn is None else batch_fn
        model_loader = load_cpu_scorer if model_loader is None else model_loader

    scorer = None

    def reuse_model(path: Path):
        nonlocal scorer
        if scorer is None:
            scorer = model_loader(path)
        return scorer

    cycles = 0
    total_processed = 0
    total_failed = 0
    total_inserted = 0
    while max_cycles is None or cycles < max_cycles:
        result = batch_fn(
            since=since, limit=limit, write_results=True,
            model_dir=model_dir, load_model=reuse_model,
        )
        if not isinstance(result, dict) or not all(
            isinstance(result.get(k), int) and not isinstance(result.get(k), bool)
            and result[k] >= 0 for k in ("selected", "processed", "failed", "inserted")
        ):
            raise RuntimeError("AI worker returned invalid batch counters")
        if (
            result["selected"] > limit
            or result["processed"] + result["failed"] > result["selected"]
            or result["inserted"] > result["selected"]
            or result.get("dry_run") is not False
        ):
            raise RuntimeError("AI worker returned inconsistent batch counters")
        cycles += 1
        total_processed += result["processed"]
        total_failed += result["failed"]
        total_inserted += result["inserted"]
        reporter(
            f"AI monitor cycle={cycles}: selected={result['selected']} "
            f"processed={result['processed']} failed={result['failed']} "
            f"inserted={result['inserted']}"
        )
        if max_cycles is None or cycles < max_cycles:
            sleep_fn(poll_seconds)
    return {"cycles": cycles, "processed": total_processed,
            "failed": total_failed, "inserted": total_inserted}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--since", required=True, help="ISO 8601 timestamp with timezone")
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument("--poll-seconds", type=float, default=10.0)
    parser.add_argument("--max-cycles", type=int, default=None,
                        help="Optional bounded monitoring for testing; otherwise run until Ctrl+C")
    parser.add_argument("--model-dir", type=Path,
                        default=Path.home() / "Downloads" / "IntelSOC-LAnoBERT-v0.2-model")
    parser.add_argument("--write-results", action="store_true",
                        help="Required for monitoring; writes only to event_ai_analysis")
    args = parser.parse_args()

    from dotenv import load_dotenv
    from lanobert_v02.ai_batch_worker import parse_since

    since = parse_since(args.since)
    validate_monitor_options(
        since=since, limit=args.limit, poll_seconds=args.poll_seconds,
        write_results=args.write_results, max_cycles=args.max_cycles,
    )
    load_dotenv(Path(__file__).resolve().parents[1] / ".env", override=True)
    print("LAnoBERT monitor: opt-in advisory-only processing (Ctrl+C to stop)")
    try:
        report = monitor(
            since=since, limit=args.limit, poll_seconds=args.poll_seconds,
            model_dir=args.model_dir, write_results=args.write_results,
            max_cycles=args.max_cycles,
        )
        print("LAnoBERT monitor stopped:", report)
    except KeyboardInterrupt:
        print("\nLAnoBERT monitor stopped by operator")


if __name__ == "__main__":
    main()
