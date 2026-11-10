import httpx
import pytest

from app.services.ti_indicator_service import ThreatIndicator
from app.services.virustotal_service import (
    lookup_virustotal,
    normalize_virustotal_response,
)


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
        self.paths = []

    def get(self, path):
        self.paths.append(path)
        if self.error is not None:
            raise self.error
        return self.response


def vt_payload(*, malicious=0, suspicious=0, harmless=0, undetected=0):
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                    "timeout": 0,
                    "failure": 0,
                    "type-unsupported": 0,
                    "confirmed-timeout": 0,
                },
                "reputation": -5,
                "last_analysis_date": 1790000000,
            }
        }
    }


def test_ip_lookup_uses_ip_addresses_endpoint():
    client = FakeClient(FakeResponse(200, vt_payload(harmless=3)))

    result = lookup_virustotal(
        ThreatIndicator("ip", "8.8.8.8"),
        api_key="test-key",
        client=client,
    )

    assert client.paths == ["/ip_addresses/8.8.8.8"]
    assert result.lookup_status == "success"
    assert result.verdict == "benign"


def test_domain_lookup_uses_domains_endpoint():
    client = FakeClient(FakeResponse(200, vt_payload(suspicious=1, harmless=3)))

    result = lookup_virustotal(
        ThreatIndicator("domain", "example.org"),
        api_key="test-key",
        client=client,
    )

    assert client.paths == ["/domains/example.org"]
    assert result.verdict == "suspicious"


@pytest.mark.parametrize(
    ("payload", "verdict", "confidence"),
    [
        (vt_payload(malicious=2, harmless=2), "malicious", 50),
        (vt_payload(suspicious=1, harmless=3), "suspicious", 25),
        (vt_payload(harmless=4), "benign", 100),
        (vt_payload(undetected=4), "unknown", None),
    ],
)
def test_normalization_maps_analysis_stats(payload, verdict, confidence):
    result = normalize_virustotal_response(
        ThreatIndicator("ip", "8.8.8.8"),
        payload,
    )

    assert result.provider == "virustotal"
    assert result.verdict == verdict
    assert result.confidence == confidence
    assert result.lookup_status == "success"
    assert result.details["reputation"] == -5


def test_404_is_not_found_not_benign():
    result = lookup_virustotal(
        ThreatIndicator("ip", "8.8.8.8"),
        api_key="test-key",
        client=FakeClient(FakeResponse(404)),
    )

    assert result.verdict == "unknown"
    assert result.lookup_status == "not_found"
    assert result.confidence is None


def test_429_is_rate_limited_not_benign():
    result = lookup_virustotal(
        ThreatIndicator("domain", "example.org"),
        api_key="test-key",
        client=FakeClient(FakeResponse(429)),
    )

    assert result.verdict == "unknown"
    assert result.lookup_status == "rate_limited"


def test_other_http_error_is_unknown_error():
    result = lookup_virustotal(
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

    result = lookup_virustotal(
        ThreatIndicator("ip", "8.8.8.8"),
        api_key="test-key",
        client=FakeClient(error=error),
    )

    assert result.verdict == "unknown"
    assert result.lookup_status == "error"
    assert result.details["error_type"] == "ReadTimeout"


def test_invalid_json_and_payload_are_errors():
    result = lookup_virustotal(
        ThreatIndicator("ip", "8.8.8.8"),
        api_key="test-key",
        client=FakeClient(
            FakeResponse(200, json_error=ValueError("bad json"))
        ),
    )
    assert result.lookup_status == "error"

    result = normalize_virustotal_response(
        ThreatIndicator("ip", "8.8.8.8"),
        {"data": {}},
    )
    assert result.lookup_status == "error"


def test_unsupported_indicator_type_rejected_before_http():
    client = FakeClient(FakeResponse(200, {}))

    with pytest.raises(ValueError, match="Unsupported VirusTotal indicator type"):
        lookup_virustotal(
            ThreatIndicator("hash", "abc"),
            api_key="test-key",
            client=client,
        )

    assert client.paths == []


def test_missing_key_and_invalid_timeout_rejected():
    indicator = ThreatIndicator("ip", "8.8.8.8")

    with pytest.raises(ValueError, match="API key"):
        lookup_virustotal(
            indicator,
            api_key="",
            client=FakeClient(FakeResponse(200, {})),
        )

    with pytest.raises(ValueError, match="timeout_seconds"):
        lookup_virustotal(
            indicator,
            api_key="test-key",
            timeout_seconds=0,
            client=FakeClient(FakeResponse(200, {})),
        )
