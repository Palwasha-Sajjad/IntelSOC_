from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.services import ti_orchestration_service as service
from app.services.ti_persistence_service import (
    AlertEvidence,
    CachedTiResult,
)
from app.services.ti_provider_result import ProviderResult


NOW = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)


def evidence(raw_event, *, source="windows_eventlog", alert_id=None, detection_id=None):
    return AlertEvidence(
        alert_id=alert_id or uuid4(),
        detection_id=detection_id or uuid4(),
        event_id=uuid4(),
        source=source,
        raw_event=raw_event,
    )


def windows_4625(ip):
    inserts = [""] * 21
    inserts[19] = ip
    return {
        "EventID": 4625,
        "Channel": "Security",
        "ProviderName": "Microsoft-Windows-Security-Auditing",
        "StringInserts": inserts,
    }


def test_no_indicators_marks_processed_without_provider_lookup(monkeypatch):
    alert_id = uuid4()
    row = evidence(windows_4625("192.168.1.8"), alert_id=alert_id)

    monkeypatch.setattr(service, "get_alert_evidence", lambda value: (row,))

    processed = []
    monkeypatch.setattr(service, "mark_alert_ti_processed", processed.append)
    monkeypatch.setattr(
        service,
        "lookup_virustotal",
        lambda *args, **kwargs: pytest.fail("Provider must not be called"),
    )

    result = service.enrich_alert_with_virustotal(
        alert_id,
        api_key="unused",
        now=NOW,
    )

    assert result.status == "processed"
    assert result.indicators == 0
    assert result.provider_lookups == 0
    assert processed == [alert_id]


def test_cache_hit_skips_provider_and_links_all_evidence(monkeypatch):
    alert_id = uuid4()
    detection_id = uuid4()
    first = evidence(
        windows_4625("8.8.8.8"),
        alert_id=alert_id,
        detection_id=detection_id,
    )
    second = evidence(
        windows_4625("8.8.8.8"),
        alert_id=alert_id,
        detection_id=detection_id,
    )
    result_id = uuid4()

    monkeypatch.setattr(
        service,
        "get_alert_evidence",
        lambda value: (first, second),
    )
    monkeypatch.setattr(
        service,
        "get_cached_ti_result",
        lambda *args, **kwargs: CachedTiResult(
            result_id=result_id,
            provider="virustotal",
            indicator_type="ip",
            indicator_value="8.8.8.8",
            verdict="benign",
            lookup_status="success",
            confidence=90,
            details={},
            checked_at=NOW - timedelta(hours=1),
            expires_at=NOW + timedelta(hours=23),
        ),
    )

    calls = []
    monkeypatch.setattr(
        service,
        "link_alert_indicator",
        lambda **kwargs: calls.append(kwargs),
    )
    monkeypatch.setattr(service, "mark_alert_ti_processed", lambda value: None)

    summary = service.enrich_alert_with_virustotal(
        alert_id,
        api_key="unused",
        now=NOW,
        lookup=lambda *args, **kwargs: pytest.fail("cache miss unexpected"),
    )

    assert summary.cache_hits == 1
    assert summary.provider_lookups == 0
    assert summary.indicators == 1
    assert summary.linked_results == 2
    assert {call["event_id"] for call in calls} == {
        first.event_id,
        second.event_id,
    }
    assert all(call["result_id"] == result_id for call in calls)


def test_cache_miss_calls_provider_once_and_persists_24h(monkeypatch):
    alert_id = uuid4()
    row = evidence(windows_4625("1.1.1.1"), alert_id=alert_id)
    stored_result_id = uuid4()

    monkeypatch.setattr(service, "get_alert_evidence", lambda value: (row,))
    monkeypatch.setattr(
        service,
        "get_cached_ti_result",
        lambda *args, **kwargs: None,
    )

    lookup_calls = []

    def fake_lookup(indicator, *, api_key):
        lookup_calls.append((indicator, api_key))
        return ProviderResult(
            provider="virustotal",
            indicator_type="ip",
            indicator_value="1.1.1.1",
            verdict="benign",
            lookup_status="success",
            confidence=80,
            details={},
        )

    persisted = []

    def fake_persist(result, *, checked_at, expires_at):
        persisted.append((result, checked_at, expires_at))
        return stored_result_id

    monkeypatch.setattr(service, "persist_ti_result", fake_persist)
    monkeypatch.setattr(service, "link_alert_indicator", lambda **kwargs: None)
    monkeypatch.setattr(service, "mark_alert_ti_processed", lambda value: None)

    summary = service.enrich_alert_with_virustotal(
        alert_id,
        api_key="secret-key",
        now=NOW,
        lookup=fake_lookup,
    )

    assert len(lookup_calls) == 1
    assert lookup_calls[0][1] == "secret-key"
    assert persisted[0][1] == NOW
    assert persisted[0][2] == NOW + timedelta(hours=24)
    assert summary.provider_lookups == 1
    assert summary.status == "processed"


@pytest.mark.parametrize("lookup_status", ["rate_limited", "error"])
def test_transient_provider_result_uses_short_cache_and_marks_failed(
    monkeypatch,
    lookup_status,
):
    alert_id = uuid4()
    row = evidence(windows_4625("9.9.9.9"), alert_id=alert_id)

    monkeypatch.setattr(service, "get_alert_evidence", lambda value: (row,))
    monkeypatch.setattr(
        service,
        "get_cached_ti_result",
        lambda *args, **kwargs: None,
    )

    monkeypatch.setattr(
        service,
        "persist_ti_result",
        lambda result, *, checked_at, expires_at: (
            pytest.fail("wrong transient TTL")
            if expires_at != NOW + timedelta(minutes=5)
            else uuid4()
        ),
    )
    monkeypatch.setattr(service, "link_alert_indicator", lambda **kwargs: None)

    failures = []
    monkeypatch.setattr(
        service,
        "mark_alert_ti_failed",
        lambda alert_id, error: failures.append((alert_id, error)),
    )

    summary = service.enrich_alert_with_virustotal(
        alert_id,
        api_key="key",
        now=NOW,
        lookup=lambda indicator, *, api_key: ProviderResult(
            provider="virustotal",
            indicator_type=indicator.indicator_type,
            indicator_value=indicator.value,
            verdict="unknown",
            lookup_status=lookup_status,
            confidence=None,
            details={},
        ),
    )

    assert summary.status == "failed"
    assert summary.provider_lookups == 1
    assert failures
    assert lookup_status in failures[0][1]


def test_not_found_is_completed_unknown_not_transient_failure(monkeypatch):
    alert_id = uuid4()
    row = evidence(windows_4625("8.8.4.4"), alert_id=alert_id)

    monkeypatch.setattr(service, "get_alert_evidence", lambda value: (row,))
    monkeypatch.setattr(
        service,
        "get_cached_ti_result",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        service,
        "persist_ti_result",
        lambda result, *, checked_at, expires_at: uuid4(),
    )
    monkeypatch.setattr(service, "link_alert_indicator", lambda **kwargs: None)

    processed = []
    failed = []
    monkeypatch.setattr(service, "mark_alert_ti_processed", processed.append)
    monkeypatch.setattr(
        service,
        "mark_alert_ti_failed",
        lambda *args: failed.append(args),
    )

    summary = service.enrich_alert_with_virustotal(
        alert_id,
        api_key="key",
        now=NOW,
        lookup=lambda indicator, *, api_key: ProviderResult(
            provider="virustotal",
            indicator_type=indicator.indicator_type,
            indicator_value=indicator.value,
            verdict="unknown",
            lookup_status="not_found",
            confidence=None,
            details={},
        ),
    )

    assert summary.status == "processed"
    assert processed == [alert_id]
    assert failed == []


def test_cached_transient_result_marks_failed_without_new_lookup(monkeypatch):
    alert_id = uuid4()
    row = evidence(windows_4625("8.8.8.8"), alert_id=alert_id)

    monkeypatch.setattr(service, "get_alert_evidence", lambda value: (row,))
    monkeypatch.setattr(
        service,
        "get_cached_ti_result",
        lambda *args, **kwargs: CachedTiResult(
            result_id=uuid4(),
            provider="virustotal",
            indicator_type="ip",
            indicator_value="8.8.8.8",
            verdict="unknown",
            lookup_status="rate_limited",
            confidence=None,
            details={},
            checked_at=NOW,
            expires_at=NOW + timedelta(minutes=4),
        ),
    )
    monkeypatch.setattr(service, "link_alert_indicator", lambda **kwargs: None)

    failures = []
    monkeypatch.setattr(
        service,
        "mark_alert_ti_failed",
        lambda alert_id, error: failures.append((alert_id, error)),
    )

    summary = service.enrich_alert_with_virustotal(
        alert_id,
        api_key="unused",
        now=NOW,
        lookup=lambda *args, **kwargs: pytest.fail("must use cache"),
    )

    assert summary.status == "failed"
    assert summary.cache_hits == 1
    assert summary.provider_lookups == 0
    assert failures


def test_ttl_validation_happens_before_persistence(monkeypatch):
    monkeypatch.setattr(
        service,
        "get_alert_evidence",
        lambda value: pytest.fail("Evidence must not be queried"),
    )

    with pytest.raises(ValueError, match="timezone-aware"):
        service.enrich_alert_with_virustotal(
            uuid4(),
            api_key="key",
            now=datetime(2026, 11, 10, 12, 0),
        )

    with pytest.raises(ValueError, match="cache_ttl"):
        service.enrich_alert_with_virustotal(
            uuid4(),
            api_key="key",
            now=NOW,
            cache_ttl=timedelta(0),
        )
