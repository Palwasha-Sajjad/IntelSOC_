from __future__ import annotations

from typing import Any

import httpx

from app.services.ti_indicator_service import ThreatIndicator
from app.services.ti_provider_result import ProviderResult


PROVIDER = "abuseipdb"
BASE_URL = "https://api.abuseipdb.com/api/v2"
DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_MAX_AGE_DAYS = 90
MALICIOUS_THRESHOLD = 75


def lookup_abuseipdb(
    indicator: ThreatIndicator,
    *,
    api_key: str,
    client: httpx.Client | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
) -> ProviderResult:
    """Retrieve and normalize one AbuseIPDB IP report."""

    key = str(api_key or "").strip()
    if not key:
        raise ValueError("AbuseIPDB API key is required")

    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")

    if not 1 <= max_age_days <= 365:
        raise ValueError("max_age_days must be between 1 and 365")

    if indicator.indicator_type != "ip":
        raise ValueError(
            f"Unsupported AbuseIPDB indicator type: {indicator.indicator_type}"
        )

    owns_client = client is None
    active_client = client or httpx.Client(
        base_url=BASE_URL,
        timeout=timeout_seconds,
        headers={
            "Accept": "application/json",
            "Key": key,
        },
    )

    try:
        try:
            response = active_client.get(
                "/check",
                params={
                    "ipAddress": indicator.value,
                    "maxAgeInDays": max_age_days,
                },
            )
        except httpx.RequestError as error:
            return _failure_result(
                indicator,
                lookup_status="error",
                details={"error_type": type(error).__name__},
            )

        if response.status_code == 404:
            return _failure_result(
                indicator,
                lookup_status="not_found",
                details={"http_status": 404},
            )

        if response.status_code == 429:
            return _failure_result(
                indicator,
                lookup_status="rate_limited",
                details={"http_status": 429},
            )

        if response.status_code != 200:
            return _failure_result(
                indicator,
                lookup_status="error",
                details={"http_status": response.status_code},
            )

        try:
            payload = response.json()
        except ValueError:
            return _failure_result(
                indicator,
                lookup_status="error",
                details={
                    "http_status": 200,
                    "error_type": "invalid_json",
                },
            )

        return normalize_abuseipdb_response(indicator, payload)
    finally:
        if owns_client:
            active_client.close()


def normalize_abuseipdb_response(
    indicator: ThreatIndicator,
    payload: Any,
) -> ProviderResult:
    """Normalize AbuseIPDB v2 check data into IntelSOC's provider contract."""

    if indicator.indicator_type != "ip":
        raise ValueError(
            f"Unsupported AbuseIPDB indicator type: {indicator.indicator_type}"
        )

    if not isinstance(payload, dict):
        return _failure_result(
            indicator,
            lookup_status="error",
            details={"error_type": "invalid_payload"},
        )

    data = payload.get("data")
    if not isinstance(data, dict):
        return _failure_result(
            indicator,
            lookup_status="error",
            details={"error_type": "missing_data"},
        )

    score = data.get("abuseConfidenceScore")
    if (
        isinstance(score, bool)
        or not isinstance(score, int)
        or not 0 <= score <= 100
    ):
        return _failure_result(
            indicator,
            lookup_status="error",
            details={"error_type": "invalid_abuse_confidence_score"},
        )

    details: dict[str, Any] = {
        "abuse_confidence_score": score,
    }

    for source_key, target_key in (
        ("totalReports", "total_reports"),
        ("lastReportedAt", "last_reported_at"),
        ("isWhitelisted", "is_whitelisted"),
        ("countryCode", "country_code"),
        ("usageType", "usage_type"),
        ("isp", "isp"),
        ("domain", "domain"),
    ):
        value = data.get(source_key)
        if value is not None:
            details[target_key] = value

    return ProviderResult(
        provider=PROVIDER,
        indicator_type=indicator.indicator_type,
        indicator_value=indicator.value,
        verdict=_verdict_from_score(score),
        lookup_status="success",
        confidence=score,
        details=details,
    )


def _verdict_from_score(score: int) -> str:
    if score >= MALICIOUS_THRESHOLD:
        return "malicious"

    if score > 0:
        return "suspicious"

    return "benign"


def _failure_result(
    indicator: ThreatIndicator,
    *,
    lookup_status: str,
    details: dict[str, Any],
) -> ProviderResult:
    return ProviderResult(
        provider=PROVIDER,
        indicator_type=indicator.indicator_type,
        indicator_value=indicator.value,
        verdict="unknown",
        lookup_status=lookup_status,
        confidence=None,
        details=details,
    )
