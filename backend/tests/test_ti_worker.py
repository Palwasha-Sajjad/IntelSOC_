from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from app.workers import ti_worker


def connection_with_cursor(cursor):
    connection = MagicMock()
    connection.cursor.return_value.__enter__.return_value = cursor

    context = MagicMock()
    context.__enter__.return_value = connection
    context.__exit__.return_value = False

    return context


def test_fetch_pending_ti_alerts_is_provider_specific(monkeypatch):
    first = uuid4()
    second = uuid4()

    cursor = MagicMock()
    cursor.fetchall.return_value = [(first,), (second,)]

    monkeypatch.setattr(
        ti_worker.psycopg,
        "connect",
        lambda **kwargs: connection_with_cursor(cursor),
    )

    result = ti_worker.fetch_pending_ti_alerts(
        provider="abuseipdb",
        limit=10,
        retry_delay_seconds=300,
    )

    assert result == [first, second]

    sql, params = cursor.execute.call_args.args
    assert "LEFT JOIN alert_ti_analysis_state AS s" in sql
    assert "s.provider = %s" in sql
    assert "s.alert_id IS NULL" in sql
    assert "s.status = 'failed'" in sql
    assert "s.updated_at <=" in sql
    assert params == ("abuseipdb", 300, 10)


@pytest.mark.parametrize(
    ("provider", "limit", "retry_delay_seconds"),
    [
        ("virustotal", 0, 300),
        ("virustotal", 10, 0),
        ("unknown", 10, 300),
    ],
)
def test_fetch_pending_ti_alerts_rejects_invalid_inputs(
    provider,
    limit,
    retry_delay_seconds,
):
    with pytest.raises(ValueError):
        ti_worker.fetch_pending_ti_alerts(
            provider=provider,
            limit=limit,
            retry_delay_seconds=retry_delay_seconds,
        )


class Summary:
    def __init__(
        self,
        *,
        status,
        provider_lookups,
        cache_hits,
        indicators,
    ):
        self.status = status
        self.provider_lookups = provider_lookups
        self.cache_hits = cache_hits
        self.indicators = indicators


def test_process_virustotal_batch_uses_vt_orchestrator(monkeypatch):
    alert_id = uuid4()

    monkeypatch.setattr(
        ti_worker,
        "fetch_pending_ti_alerts",
        lambda **kwargs: [alert_id],
    )
    monkeypatch.setattr(
        ti_worker,
        "enrich_alert_with_virustotal",
        lambda alert_id, api_key: Summary(
            status="processed",
            provider_lookups=1,
            cache_hits=0,
            indicators=1,
        ),
    )
    monkeypatch.setattr(
        ti_worker,
        "enrich_alert_with_abuseipdb",
        lambda *args, **kwargs: pytest.fail(
            "AbuseIPDB must not run in VT batch"
        ),
    )

    result = ti_worker.process_ti_batch(
        provider="virustotal",
        api_key="vt-key",
    )

    assert result["alerts_selected"] == 1
    assert result["alerts_processed"] == 1
    assert result["provider_lookups"] == 1


def test_process_abuseipdb_batch_uses_abuse_orchestrator(monkeypatch):
    alert_id = uuid4()

    monkeypatch.setattr(
        ti_worker,
        "fetch_pending_ti_alerts",
        lambda **kwargs: [alert_id],
    )
    monkeypatch.setattr(
        ti_worker,
        "enrich_alert_with_abuseipdb",
        lambda alert_id, api_key: Summary(
            status="processed",
            provider_lookups=1,
            cache_hits=0,
            indicators=1,
        ),
    )
    monkeypatch.setattr(
        ti_worker,
        "enrich_alert_with_virustotal",
        lambda *args, **kwargs: pytest.fail(
            "VirusTotal must not run in AbuseIPDB batch"
        ),
    )

    result = ti_worker.process_ti_batch(
        provider="abuseipdb",
        api_key="abuse-key",
    )

    assert result["alerts_selected"] == 1
    assert result["alerts_processed"] == 1
    assert result["provider_lookups"] == 1


def test_process_batch_marks_exception_failed_for_same_provider(monkeypatch):
    alert_id = uuid4()

    monkeypatch.setattr(
        ti_worker,
        "fetch_pending_ti_alerts",
        lambda **kwargs: [alert_id],
    )
    monkeypatch.setattr(
        ti_worker,
        "enrich_alert_with_abuseipdb",
        lambda alert_id, api_key: (_ for _ in ()).throw(
            RuntimeError("database unavailable")
        ),
    )

    failures = []
    monkeypatch.setattr(
        ti_worker,
        "mark_alert_ti_failed",
        lambda alert_id, error, provider="virustotal": failures.append(
            (alert_id, error, provider)
        ),
    )

    result = ti_worker.process_ti_batch(
        provider="abuseipdb",
        api_key="test-key",
    )

    assert result["alerts_failed"] == 1
    assert failures == [
        (alert_id, "database unavailable", "abuseipdb")
    ]


@pytest.mark.parametrize(
    ("provider", "message"),
    [
        ("virustotal", "VT_API_KEY"),
        ("abuseipdb", "ABUSEIPDB_KEY"),
    ],
)
def test_process_batch_requires_provider_key_before_selecting(
    monkeypatch,
    provider,
    message,
):
    monkeypatch.setattr(
        ti_worker,
        "fetch_pending_ti_alerts",
        lambda **kwargs: pytest.fail(
            "Worker must reject missing key first"
        ),
    )

    with pytest.raises(ValueError, match=message):
        ti_worker.process_ti_batch(
            provider=provider,
            api_key="",
        )


def test_main_requires_both_configured_keys(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "vt-key")
    monkeypatch.delenv("ABUSEIPDB_KEY", raising=False)

    with pytest.raises(RuntimeError, match="ABUSEIPDB_KEY"):
        ti_worker.main()


def test_provider_normalization_rejects_unknown():
    with pytest.raises(ValueError, match="unsupported TI provider"):
        ti_worker.process_ti_batch(
            provider="otx",
            api_key="key",
        )
