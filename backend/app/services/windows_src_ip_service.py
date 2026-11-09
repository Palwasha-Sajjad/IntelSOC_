"""Safe, bounded enrichment of existing Windows Security Event 4625 rows.

Does not alter ingestion, raw_event, device_id, or downstream detections.
Dry-run by default. Each run examines at most 'limit' candidate rows.
"""
import ipaddress
from dataclasses import dataclass
from uuid import UUID

import psycopg

from app.analysis.windows_event_extractor import extract_windows_failed_logon
from app.core.config import get_postgres_config


@dataclass(frozen=True)
class EnrichmentReport:
    examined: int
    valid_ips: int
    updated: int
    dry_run: bool
    next_after_event_id: str | None


def source_ip_from_4625(raw_event: object) -> str | None:
    """Return a canonical, non-unspecified IP from an authenticated-shaped 4625.

    Parsing is based solely on event evidence, never guessed from device
    address, hostname, or an unrelated event's Message.
    """
    if not isinstance(raw_event, dict):
        return None

    evidence = extract_windows_failed_logon(raw_event)
    if evidence is None or evidence.source_ip is None:
        return None

    try:
        address = ipaddress.ip_address(evidence.source_ip)
    except ValueError:
        return None
    if address.is_unspecified:
        return None

    return str(address)


def enrich_stored_windows_4625_ips(
    *, limit: int = 500, apply: bool = False,
    after_event_id: UUID | str | None = None,
) -> EnrichmentReport:
    """Scan a bounded set of stored events and optionally fill missing IPs.

    Never overwrites a previously stored value. No database mutation takes
    place in dry-run mode. Existing raw_event and device_id are untouched.
    """
    if not 1 <= limit <= 5000:
        raise ValueError("limit must be between 1 and 5000")

    if after_event_id is not None:
        after_event_id = UUID(str(after_event_id))

    with psycopg.connect(
        **get_postgres_config(), connect_timeout=5,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT event_id, raw_event
                FROM security_events
                WHERE source = 'windows_eventlog'
                  AND event_type = 'windows_security_event'
                  AND raw_event->>'EventID' = '4625'
                  AND src_ip IS NULL
                  AND device_id IS NOT NULL
                  AND (%s::uuid IS NULL OR event_id > %s::uuid)
                ORDER BY event_id
                LIMIT %s
                """,
                (after_event_id, after_event_id, limit),
            )
            rows = cursor.fetchall()

            valid_ips = 0
            updated = 0

            for event_id, raw_event in rows:
                source_ip = source_ip_from_4625(raw_event)
                if source_ip is None:
                    continue

                valid_ips += 1
                if not apply:
                    continue

                cursor.execute(
                    """
                    UPDATE security_events
                    SET src_ip = %s
                    WHERE event_id = %s
                      AND src_ip IS NULL
                      AND source = 'windows_eventlog'
                      AND event_type = 'windows_security_event'
                      AND device_id IS NOT NULL
                      AND raw_event->>'EventID' = '4625'
                    """,
                    (source_ip, event_id),
                )
                updated += cursor.rowcount

            if not apply:
                connection.rollback()

    return EnrichmentReport(
        examined=len(rows), valid_ips=valid_ips,
        updated=updated, dry_run=not apply,
        next_after_event_id=str(rows[-1][0]) if rows else None,
    )
