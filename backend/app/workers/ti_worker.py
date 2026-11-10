import os
import time
from pathlib import Path
from uuid import UUID

import psycopg
from dotenv import load_dotenv

from app.core.config import get_postgres_config
from app.services.ti_orchestration_service import (
    enrich_alert_with_abuseipdb,
    enrich_alert_with_virustotal,
)
from app.services.ti_persistence_service import mark_alert_ti_failed


ROOT = Path(__file__).resolve().parents[3]
load_dotenv(ROOT / ".env")

POLL_SECONDS = 1.0
BATCH_SIZE = 20
RETRY_DELAY_SECONDS = 300
SUPPORTED_PROVIDERS = {"virustotal", "abuseipdb"}


def fetch_pending_ti_alerts(
    *,
    provider: str = "virustotal",
    limit: int = BATCH_SIZE,
    retry_delay_seconds: int = RETRY_DELAY_SECONDS,
) -> list[UUID]:
    """Return new alerts plus retryable failures for one TI provider."""

    provider = _normalize_provider(provider)

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
                LEFT JOIN alert_ti_analysis_state AS s
                  ON s.alert_id = a.alert_id
                 AND s.provider = %s
                WHERE
                    s.alert_id IS NULL
                    OR (
                        s.status = 'failed'
                        AND s.updated_at <= (
                            NOW() - (%s * INTERVAL '1 second')
                        )
                    )
                ORDER BY a.created_at ASC, a.alert_id ASC
                LIMIT %s
                """,
                (
                    provider,
                    retry_delay_seconds,
                    limit,
                ),
            )

            rows = cursor.fetchall()

    return [UUID(str(row[0])) for row in rows]


def process_ti_batch(
    *,
    provider: str = "virustotal",
    api_key: str,
    limit: int = BATCH_SIZE,
    retry_delay_seconds: int = RETRY_DELAY_SECONDS,
) -> dict[str, int]:
    """Process one bounded provider-specific TI batch."""

    provider = _normalize_provider(provider)
    key = str(api_key or "").strip()
    if not key:
        env_name = _provider_env_name(provider)
        raise ValueError(f"{env_name} is required")

    alert_ids = fetch_pending_ti_alerts(
        provider=provider,
        limit=limit,
        retry_delay_seconds=retry_delay_seconds,
    )

    result = {
        "alerts_selected": len(alert_ids),
        "alerts_processed": 0,
        "alerts_failed": 0,
        "provider_lookups": 0,
        "cache_hits": 0,
        "indicators": 0,
    }

    enrich = (
        enrich_alert_with_virustotal
        if provider == "virustotal"
        else enrich_alert_with_abuseipdb
    )

    for alert_id in alert_ids:
        try:
            summary = enrich(
                alert_id,
                api_key=key,
            )

            result["provider_lookups"] += summary.provider_lookups
            result["cache_hits"] += summary.cache_hits
            result["indicators"] += summary.indicators

            if summary.status == "processed":
                result["alerts_processed"] += 1
            else:
                result["alerts_failed"] += 1

        except Exception as error:
            result["alerts_failed"] += 1

            try:
                mark_alert_ti_failed(
                    alert_id,
                    str(error),
                    provider=provider,
                )
            except Exception as state_error:
                print(
                    "TI worker could not persist failure state for "
                    f"{provider} alert {alert_id}: {state_error}",
                    flush=True,
                )

            print(
                f"TI enrichment failed for {provider} alert "
                f"{alert_id}: {error}",
                flush=True,
            )

    return result


def main() -> None:
    keys = {
        "virustotal": str(os.getenv("VT_API_KEY") or "").strip(),
        "abuseipdb": str(os.getenv("ABUSEIPDB_KEY") or "").strip(),
    }

    missing = [
        _provider_env_name(provider)
        for provider, key in keys.items()
        if not key
    ]
    if missing:
        raise RuntimeError(
            "Missing TI API key(s): " + ", ".join(missing)
        )

    print("IntelSOC TI worker started", flush=True)

    while True:
        try:
            for provider in ("virustotal", "abuseipdb"):
                result = process_ti_batch(
                    provider=provider,
                    api_key=keys[provider],
                )

                if result["alerts_selected"]:
                    print(
                        f"TI batch provider={provider}: "
                        f"selected={result['alerts_selected']} "
                        f"processed={result['alerts_processed']} "
                        f"failed={result['alerts_failed']} "
                        f"lookups={result['provider_lookups']} "
                        f"cache_hits={result['cache_hits']}",
                        flush=True,
                    )

        except (psycopg.Error, OSError) as error:
            print(
                f"TI worker database error: {error}",
                flush=True,
            )

        time.sleep(POLL_SECONDS)


def _normalize_provider(provider: str) -> str:
    value = str(provider or "").strip().lower()
    if value not in SUPPORTED_PROVIDERS:
        raise ValueError("unsupported TI provider")
    return value


def _provider_env_name(provider: str) -> str:
    if provider == "virustotal":
        return "VT_API_KEY"
    if provider == "abuseipdb":
        return "ABUSEIPDB_KEY"
    raise ValueError("unsupported TI provider")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nTI worker stopped", flush=True)
