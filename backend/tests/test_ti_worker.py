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


def test_fetch_pending_ti_alerts_selects_new_and_retryable(monkeypatch):
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
        limit=10,
        retry_delay_seconds=300,
    )

    assert result == [first, second]

    sql, params = cursor.execute.call_args.args
    assert "LEFT JOIN alert_ti_analysis_state AS s" in sql
    assert "s.alert_id IS NULL" in sql
    assert "s.status = 'failed'" in sql
    assert "s.updated_at <=" in sql
    assert params == (300, 10)


@pytest.mark.parametrize(
    ("limit", "retry_delay_seconds"),
    [(0, 300), (10, 0)],
)
def test_fetch_pending_ti_alerts_rejects_invalid_bounds(
    limit,
    retry_delay_seconds,
):
    with pytest.raises(ValueError):
        ti_worker.fetch_pending_ti_alerts(
            limit=limit,
            retry_delay_seconds=retry_delay_seconds,
        )


def test_process_batch_counts_success_failure_and_cache(monkeypatch):
    first = uuid4()
    second = uuid4()

    monkeypatch.setattr(
        ti_worker,
        "fetch_pending_ti_alerts",
        lambda **kwargs: [first, second],
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

    summaries = {
        first: Summary(
            status="processed",
            provider_lookups=1,
            cache_hits=0,
            indicators=1,
        ),
        second: Summary(
            status="failed",
            provider_lookups=0,
            cache_hits=1,
            indicators=1,
        ),
    }

    monkeypatch.setattr(
        ti_worker,
        "enrich_alert_with_virustotal",
        lambda alert_id, api_key: summaries[alert_id],
    )

    result = ti_worker.process_ti_batch(
        api_key="test-key",
    )

    assert result == {
        "alerts_selected": 2,
        "alerts_processed": 1,
        "alerts_failed": 1,
        "provider_lookups": 1,
        "cache_hits": 1,
        "indicators": 2,
    }


def test_process_batch_marks_unexpected_exception_failed(monkeypatch):
    alert_id = uuid4()

    monkeypatch.setattr(
        ti_worker,
        "fetch_pending_ti_alerts",
        lambda **kwargs: [alert_id],
    )

    monkeypatch.setattr(
        ti_worker,
        "enrich_alert_with_virustotal",
        lambda alert_id, api_key: (_ for _ in ()).throw(
            RuntimeError("database unavailable")
        ),
    )

    failures = []
    monkeypatch.setattr(
        ti_worker,
        "mark_alert_ti_failed",
        lambda alert_id, error: failures.append(
            (alert_id, error)
        ),
    )

    result = ti_worker.process_ti_batch(
        api_key="test-key",
    )

    assert result["alerts_selected"] == 1
    assert result["alerts_processed"] == 0
    assert result["alerts_failed"] == 1
    assert failures == [
        (alert_id, "database unavailable")
    ]


def test_process_batch_requires_key_before_selecting(monkeypatch):
    monkeypatch.setattr(
        ti_worker,
        "fetch_pending_ti_alerts",
        lambda **kwargs: pytest.fail(
            "Worker must reject missing key first"
        ),
    )

    with pytest.raises(ValueError, match="VT_API_KEY"):
        ti_worker.process_ti_batch(
            api_key="",
        )


def test_main_requires_configured_key(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)

    with pytest.raises(RuntimeError, match="VT_API_KEY"):
        ti_worker.main()
