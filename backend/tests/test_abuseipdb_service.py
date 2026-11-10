import httpx
import pytest

from app.services.abuseipdb_service import (
    lookup_abuseipdb,
    normalize_abuseipdb_response,
)
from app.services.ti_indicator_service import ThreatIndicator


class FakeResponse:
    def __init__(self, status_code, payload=None, json_error=None):
        self.status_code = status_code
        self._payload = payload
        self._json_error = json_error

    def json(self):
        if self._json_error is not None:
            raise self._json_error
        return self._payload


class FakeClient:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.calls = []

    def get(self, path, *, params=None):
        self.calls.append((path, params))
        if self.error is not None:
            raise self.error
        return self.response


def abuse_payload(score, *, total_reports=0):
    return {
        "data": {
            "ipAddress": "8.8.8.8",
            "abuseConfidenceScore": score,
            "totalReports": total_reports,
            "lastReportedAt": "2026-11-01T10:00:00+00:00",
            "isWhitelisted": False,
            "countryCode": "US",
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "Example ISP",
            "domain": "example.net",
        }
    }


def test_lookup_uses_check_endpoint_and_expected_params():
    client = FakeClient(FakeResponse(200, abuse_payload(0)))

    result = lookup_abuseipdb(
        ThreatIndicator("ip", "8.8.8.8"),
        api_key="test-key",
        client=client,
    )

    assert client.calls == [
        (
            "/check",
            {
                "ipAddress": "8.8.8.8",
                "maxAgeInDays": 90,
            },
        )
    ]
    assert result.provider == "abuseipdb"
    assert result.lookup_status == "success"


@pytest.mark.parametrize(
    ("score", "verdict"),
    [
        (0, "benign"),
        (1, "suspicious"),
        (74, "suspicious"),
        (75, "malicious"),
        (100, "malicious"),
    ],
)
def test_normalization_maps_score_to_local_verdict(score, verdict):
    result = normalize_abuseipdb_response(
        ThreatIndicator("ip", "8.8.8.8"),
        abuse_payload(score, total_reports=12),
    )

    assert result.provider == "abuseipdb"
    assert result.verdict == verdict
    assert result.lookup_status == "success"
    assert result.confidence == score
    assert result.details["abuse_confidence_score"] == score
    assert result.details["total_reports"] == 12


def test_404_is_not_found_not_benign():
    result = lookup_abuseipdb(
        ThreatIndicator("ip", "8.8.8.8"),
        api_key="test-key",
        client=FakeClient(FakeResponse(404)),
    )

    assert result.verdict == "unknown"
    assert result.lookup_status == "not_found"
    assert result.confidence is None


def test_429_is_rate_limited_not_benign():
    result = lookup_abuseipdb(
        ThreatIndicator("ip", "8.8.8.8"),
        api_key="test-key",
        client=FakeClient(FakeResponse(429)),
    )

    assert result.verdict == "unknown"
    assert result.lookup_status == "rate_limited"


def test_other_http_error_is_unknown_error():
    result = lookup_abuseipdb(
        ThreatIndicator("ip", "8.8.8.8"),
        api_key="test-key",
        client=FakeClient(FakeResponse(503)),
    )

    assert result.verdict == "unknown"
    assert result.lookup_status == "error"
    assert result.details == {"http_status": 503}


def test_request_error_is_non_throwing_provider_error():
    request = httpx.Request("GET", "https://example.invalid")
    error = httpx.ReadTimeout("timeout", request=request)

    result = lookup_abuseipdb(
        ThreatIndicator("ip", "8.8.8.8"),
        api_key="test-key",
        client=FakeClient(error=error),
    )

    assert result.verdict == "unknown"
    assert result.lookup_status == "error"
    assert result.details["error_type"] == "ReadTimeout"


def test_invalid_json_payload_and_score_are_errors():
    result = lookup_abuseipdb(
        ThreatIndicator("ip", "8.8.8.8"),
        api_key="test-key",
        client=FakeClient(
            FakeResponse(200, json_error=ValueError("bad json"))
        ),
    )
    assert result.lookup_status == "error"

    result = normalize_abuseipdb_response(
        ThreatIndicator("ip", "8.8.8.8"),
        {"data": {}},
    )
    assert result.lookup_status == "error"

    result = normalize_abuseipdb_response(
        ThreatIndicator("ip", "8.8.8.8"),
        {"data": {"abuseConfidenceScore": 101}},
    )
    assert result.lookup_status == "error"


def test_domain_indicator_is_rejected_before_http():
    client = FakeClient(FakeResponse(200, abuse_payload(0)))

    with pytest.raises(ValueError, match="Unsupported AbuseIPDB indicator type"):
        lookup_abuseipdb(
            ThreatIndicator("domain", "example.com"),
            api_key="test-key",
            client=client,
        )

    assert client.calls == []


def test_missing_key_invalid_timeout_and_max_age_rejected():
    indicator = ThreatIndicator("ip", "8.8.8.8")
    client = FakeClient(FakeResponse(200, abuse_payload(0)))

    with pytest.raises(ValueError, match="API key"):
        lookup_abuseipdb(indicator, api_key="", client=client)

    with pytest.raises(ValueError, match="timeout_seconds"):
        lookup_abuseipdb(
            indicator,
            api_key="key",
            timeout_seconds=0,
            client=client,
        )

    with pytest.raises(ValueError, match="max_age_days"):
        lookup_abuseipdb(
            indicator,
            api_key="key",
            max_age_days=0,
            client=client,
        )

    with pytest.raises(ValueError, match="max_age_days"):
        lookup_abuseipdb(
            indicator,
            api_key="key",
            max_age_days=366,
            client=client,
        )
