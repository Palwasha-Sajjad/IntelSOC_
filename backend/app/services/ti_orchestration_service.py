from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable
from uuid import UUID

from app.services.ti_indicator_service import (
    ThreatIndicator,
    extract_indicators_from_event,
)
from app.services.ti_persistence_service import (
    CachedTiResult,
    get_alert_evidence,
    get_cached_ti_result,
    link_alert_indicator,
    mark_alert_ti_failed,
    mark_alert_ti_processed,
    persist_ti_result,
)
from app.services.abuseipdb_service import lookup_abuseipdb
from app.services.ti_provider_result import ProviderResult
from app.services.virustotal_service import lookup_virustotal


DEFAULT_CACHE_TTL = timedelta(hours=24)
TRANSIENT_CACHE_TTL = timedelta(minutes=5)
_TRANSIENT_STATUSES = {"rate_limited", "error"}


@dataclass(frozen=True)
class AlertTiSummary:
    alert_id: UUID
    evidence_events: int
    indicators: int
    cache_hits: int
    provider_lookups: int
    linked_results: int
    status: str


def enrich_alert_with_virustotal(
    alert_id: UUID | str,
    *,
    api_key: str,
    now: datetime | None = None,
    cache_ttl: timedelta = DEFAULT_CACHE_TTL,
    transient_cache_ttl: timedelta = TRANSIENT_CACHE_TTL,
    lookup: Callable[..., ProviderResult] = lookup_virustotal,
) -> AlertTiSummary:
    """Enrich one alert using only its persisted detection evidence.

    This function is cache-first and idempotent. It does not alter alert
    severity, incident state, detection data, or response actions.
    """

    current_time = now or datetime.now(timezone.utc)
    _validate_time_and_ttls(
        current_time,
        cache_ttl,
        transient_cache_ttl,
    )

    evidence_rows = get_alert_evidence(alert_id)

    indicator_events: dict[ThreatIndicator, set[UUID]] = {}

    for evidence in evidence_rows:
        event = {
            "source": evidence.source,
            "raw_event": evidence.raw_event,
        }

        for indicator in extract_indicators_from_event(event):
            indicator_events.setdefault(indicator, set()).add(
                evidence.event_id
            )

    if not indicator_events:
        mark_alert_ti_processed(alert_id, provider="virustotal")
        return AlertTiSummary(
            alert_id=UUID(str(alert_id)),
            evidence_events=len(evidence_rows),
            indicators=0,
            cache_hits=0,
            provider_lookups=0,
            linked_results=0,
            status="processed",
        )

    cache_hits = 0
    provider_lookups = 0
    linked_results = 0
    transient_failures: list[str] = []

    for indicator in sorted(indicator_events):
        cached = get_cached_ti_result(
            "virustotal",
            indicator.indicator_type,
            indicator.value,
            now=current_time,
        )

        if cached is not None:
            cache_hits += 1
            result_id = cached.result_id
            lookup_status = cached.lookup_status
        else:
            provider_result = lookup(
                indicator,
                api_key=api_key,
            )
            provider_lookups += 1

            ttl = (
                transient_cache_ttl
                if provider_result.lookup_status in _TRANSIENT_STATUSES
                else cache_ttl
            )

            result_id = persist_ti_result(
                provider_result,
                checked_at=current_time,
                expires_at=current_time + ttl,
            )
            lookup_status = provider_result.lookup_status

        for event_id in sorted(
            indicator_events[indicator],
            key=str,
        ):
            link_alert_indicator(
                alert_id=alert_id,
                event_id=event_id,
                result_id=result_id,
            )
            linked_results += 1

        if lookup_status in _TRANSIENT_STATUSES:
            transient_failures.append(
                f"{indicator.indicator_type}:{indicator.value}:"
                f"{lookup_status}"
            )

    if transient_failures:
        error = "Transient TI lookup failure(s): " + ", ".join(
            transient_failures
        )
        mark_alert_ti_failed(alert_id, error, provider="virustotal")

        return AlertTiSummary(
            alert_id=UUID(str(alert_id)),
            evidence_events=len(evidence_rows),
            indicators=len(indicator_events),
            cache_hits=cache_hits,
            provider_lookups=provider_lookups,
            linked_results=linked_results,
            status="failed",
        )

    mark_alert_ti_processed(alert_id, provider="virustotal")

    return AlertTiSummary(
        alert_id=UUID(str(alert_id)),
        evidence_events=len(evidence_rows),
        indicators=len(indicator_events),
        cache_hits=cache_hits,
        provider_lookups=provider_lookups,
        linked_results=linked_results,
        status="processed",
    )



def enrich_alert_with_abuseipdb(
    alert_id: UUID | str,
    *,
    api_key: str,
    now: datetime | None = None,
    cache_ttl: timedelta = DEFAULT_CACHE_TTL,
    transient_cache_ttl: timedelta = TRANSIENT_CACHE_TTL,
    lookup: Callable[..., ProviderResult] = lookup_abuseipdb,
) -> AlertTiSummary:
    """Enrich one alert with AbuseIPDB using evidence-backed public IPs only."""

    current_time = now or datetime.now(timezone.utc)
    _validate_time_and_ttls(
        current_time,
        cache_ttl,
        transient_cache_ttl,
    )

    evidence_rows = get_alert_evidence(alert_id)
    indicator_events: dict[ThreatIndicator, set[UUID]] = {}

    for evidence in evidence_rows:
        event = {
            "source": evidence.source,
            "raw_event": evidence.raw_event,
        }

        for indicator in extract_indicators_from_event(event):
            if indicator.indicator_type != "ip":
                continue

            indicator_events.setdefault(indicator, set()).add(
                evidence.event_id
            )

    if not indicator_events:
        mark_alert_ti_processed(alert_id, provider="abuseipdb")
        return AlertTiSummary(
            alert_id=UUID(str(alert_id)),
            evidence_events=len(evidence_rows),
            indicators=0,
            cache_hits=0,
            provider_lookups=0,
            linked_results=0,
            status="processed",
        )

    cache_hits = 0
    provider_lookups = 0
    linked_results = 0
    transient_failures: list[str] = []

    for indicator in sorted(indicator_events):
        cached = get_cached_ti_result(
            "abuseipdb",
            indicator.indicator_type,
            indicator.value,
            now=current_time,
        )

        if cached is not None:
            cache_hits += 1
            result_id = cached.result_id
            lookup_status = cached.lookup_status
        else:
            provider_result = lookup(
                indicator,
                api_key=api_key,
            )
            provider_lookups += 1

            ttl = (
                transient_cache_ttl
                if provider_result.lookup_status in _TRANSIENT_STATUSES
                else cache_ttl
            )

            result_id = persist_ti_result(
                provider_result,
                checked_at=current_time,
                expires_at=current_time + ttl,
            )
            lookup_status = provider_result.lookup_status

        for event_id in sorted(
            indicator_events[indicator],
            key=str,
        ):
            link_alert_indicator(
                alert_id=alert_id,
                event_id=event_id,
                result_id=result_id,
            )
            linked_results += 1

        if lookup_status in _TRANSIENT_STATUSES:
            transient_failures.append(
                f"{indicator.indicator_type}:{indicator.value}:"
                f"{lookup_status}"
            )

    if transient_failures:
        error = "Transient TI lookup failure(s): " + ", ".join(
            transient_failures
        )
        mark_alert_ti_failed(alert_id, error, provider="abuseipdb")

        return AlertTiSummary(
            alert_id=UUID(str(alert_id)),
            evidence_events=len(evidence_rows),
            indicators=len(indicator_events),
            cache_hits=cache_hits,
            provider_lookups=provider_lookups,
            linked_results=linked_results,
            status="failed",
        )

    mark_alert_ti_processed(alert_id, provider="abuseipdb")

    return AlertTiSummary(
        alert_id=UUID(str(alert_id)),
        evidence_events=len(evidence_rows),
        indicators=len(indicator_events),
        cache_hits=cache_hits,
        provider_lookups=provider_lookups,
        linked_results=linked_results,
        status="processed",
    )

def _validate_time_and_ttls(
    now: datetime,
    cache_ttl: timedelta,
    transient_cache_ttl: timedelta,
) -> None:
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")

    if cache_ttl <= timedelta(0):
        raise ValueError("cache_ttl must be positive")

    if transient_cache_ttl <= timedelta(0):
        raise ValueError("transient_cache_ttl must be positive")
