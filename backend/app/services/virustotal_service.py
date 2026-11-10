from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx

from app.services.ti_indicator_service import ThreatIndicator
from app.services.ti_provider_result import ProviderResult


PROVIDER = "virustotal"
BASE_URL = "https://www.virustotal.com/api/v3"
DEFAULT_TIMEOUT_SECONDS = 5.0


def lookup_virustotal(
    indicator: ThreatIndicator,
    *,
    api_key: str,
    client: httpx.Client | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> ProviderResult:
    """Retrieve and normalize one VirusTotal report.

    This function performs report lookup only. It never submits files, URLs,
    raw logs, hostnames, usernames, or command lines to VirusTotal.
    """

    key = str(api_key or "").strip()
    if not key:
        raise ValueError("VirusTotal API key is required")

    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")

    path = _report_path(indicator)

    owns_client = client is None
    active_client = client or httpx.Client(
        base_url=BASE_URL,
        timeout=timeout_seconds,
        headers={
            "accept": "application/json",
            "x-apikey": key,
        },
    )

    try:
        try:
            response = active_client.get(path)
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

        return normalize_virustotal_response(indicator, payload)
    finally:
        if owns_client:
            active_client.close()


def normalize_virustotal_response(
    indicator: ThreatIndicator,
    payload: Any,
) -> ProviderResult:
    """Normalize a successful VirusTotal v3 object into IntelSOC's shape."""

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

    attributes = data.get("attributes")
    if not isinstance(attributes, dict):
        return _failure_result(
            indicator,
            lookup_status="error",
            details={"error_type": "missing_attributes"},
        )

    stats = attributes.get("last_analysis_stats")
    if not isinstance(stats, dict):
        stats = {}

    normalized_stats = _normalize_stats(stats)
    verdict = _verdict_from_stats(normalized_stats)
    confidence = _confidence_from_stats(normalized_stats, verdict)

    details: dict[str, Any] = {
        "analysis_stats": normalized_stats,
    }

    reputation = attributes.get("reputation")
    if isinstance(reputation, int) and not isinstance(reputation, bool):
        details["reputation"] = reputation

    last_analysis_date = attributes.get("last_analysis_date")
    if isinstance(last_analysis_date, int) and not isinstance(
        last_analysis_date, bool
    ):
        details["last_analysis_date"] = last_analysis_date

    return ProviderResult(
        provider=PROVIDER,
        indicator_type=indicator.indicator_type,
        indicator_value=indicator.value,
        verdict=verdict,
        lookup_status="success",
        confidence=confidence,
        details=details,
    )


def _report_path(indicator: ThreatIndicator) -> str:
    if indicator.indicator_type == "ip":
        collection = "ip_addresses"
    elif indicator.indicator_type == "domain":
        collection = "domains"
    else:
        raise ValueError(
            f"Unsupported VirusTotal indicator type: {indicator.indicator_type}"
        )

    encoded = quote(indicator.value, safe="")
    return f"/{collection}/{encoded}"


def _normalize_stats(stats: dict[str, Any]) -> dict[str, int]:
    categories = (
        "malicious",
        "suspicious",
        "harmless",
        "undetected",
        "timeout",
        "failure",
        "type-unsupported",
        "confirmed-timeout",
    )

    normalized: dict[str, int] = {}

    for category in categories:
        value = stats.get(category, 0)

        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            normalized[category] = 0
        else:
            normalized[category] = value

    return normalized


def _verdict_from_stats(stats: dict[str, int]) -> str:
    if stats["malicious"] > 0:
        return "malicious"

    if stats["suspicious"] > 0:
        return "suspicious"

    if stats["harmless"] > 0:
        return "benign"

    return "unknown"


def _confidence_from_stats(
    stats: dict[str, int],
    verdict: str,
) -> int | None:
    total = sum(stats.values())
    if total <= 0:
        return None

    if verdict == "malicious":
        decisive = stats["malicious"]
    elif verdict == "suspicious":
        decisive = stats["suspicious"]
    elif verdict == "benign":
        decisive = stats["harmless"]
    else:
        return None

    return round((decisive / total) * 100)


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
