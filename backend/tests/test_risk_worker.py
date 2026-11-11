from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from app.workers import risk_worker


def connection_with_cursor(cursor):
    connection = MagicMock()
    connection.cursor.return_value.__enter__.return_value = cursor

    context = MagicMock()
    context.__enter__.return_value = connection
    context.__exit__.return_value = False
    return context


def test_fetch_pending_risk_alerts_requires_completed_ti(monkeypatch):
    alert_id = uuid4()
    cursor = MagicMock()
    cursor.fetchall.return_value = [(alert_id,)]

    monkeypatch.setattr(
        risk_worker.psycopg,
        "connect",
        lambda **kwargs: connection_with_cursor(cursor),
    )

    result = risk_worker.fetch_pending_risk_alerts(
        limit=10,
        retry_delay_seconds=30,
    )

    assert result == [alert_id]
    sql, params = cursor.execute.call_args.args

    assert "vt.provider = 'virustotal'" in sql
    assert "vt.status = 'processed'" in sql
    assert "abuse.provider = 'abuseipdb'" in sql
    assert "abuse.status = 'processed'" in sql
    assert "ai.updated_at > ra.updated_at" in sql
    assert "tr.updated_at > ra.updated_at" in sql
    assert params == (30, 10)


@pytest.mark.parametrize(
    ("limit", "retry_delay"),
    [(0, 30), (10, 0)],
)
def test_fetch_pending_risk_alerts_rejects_invalid_bounds(
    limit,
    retry_delay,
):
    with pytest.raises(ValueError):
        risk_worker.fetch_pending_risk_alerts(
            limit=limit,
            retry_delay_seconds=retry_delay,
        )


def test_process_risk_batch_persists_success_state(monkeypatch):
    alert_id = uuid4()

    class Assessment:
        classification = "malicious"
        overall_score = 80
        rule_score = 50
        ti_score = 25
        lanobert_score = 5

    monkeypatch.setattr(
        risk_worker,
        "fetch_pending_risk_alerts",
        lambda **kwargs: [alert_id],
    )
    monkeypatch.setattr(
        risk_worker,
        "assess_alert_risk",
        lambda alert_id: Assessment(),
    )

    processed = []
    monkeypatch.setattr(
        risk_worker,
        "mark_risk_processed",
        lambda alert_id: processed.append(alert_id),
    )

    result = risk_worker.process_risk_batch()

    assert processed == [alert_id]
    assert result["alerts_processed"] == 1
    assert result["malicious"] == 1
    assert result["alerts_failed"] == 0


def test_process_risk_batch_records_failure(monkeypatch):
    alert_id = uuid4()

    monkeypatch.setattr(
        risk_worker,
        "fetch_pending_risk_alerts",
        lambda **kwargs: [alert_id],
    )
    monkeypatch.setattr(
        risk_worker,
        "assess_alert_risk",
        lambda alert_id: (_ for _ in ()).throw(
            RuntimeError("scoring failed")
        ),
    )

    failures = []
    monkeypatch.setattr(
        risk_worker,
        "mark_risk_failed",
        lambda alert_id, error: failures.append((alert_id, error)),
    )

    result = risk_worker.process_risk_batch()

    assert result["alerts_failed"] == 1
    assert failures == [(alert_id, "scoring failed")]


def test_validate_risk_schema_checks_all_required_tables(monkeypatch):
    cursor = MagicMock()
    cursor.fetchone.side_effect = [
        ("alert_ai_evidence",),
        ("alert_risk_assessments",),
        ("alert_risk_analysis_state",),
    ]

    monkeypatch.setattr(
        risk_worker.psycopg,
        "connect",
        lambda **kwargs: connection_with_cursor(cursor),
    )

    risk_worker.validate_risk_schema()

    assert cursor.execute.call_count == 3


def test_validate_risk_schema_fails_when_table_missing(monkeypatch):
    cursor = MagicMock()
    cursor.fetchone.side_effect = [
        ("alert_ai_evidence",),
        (None,),
    ]

    monkeypatch.setattr(
        risk_worker.psycopg,
        "connect",
        lambda **kwargs: connection_with_cursor(cursor),
    )

    with pytest.raises(RuntimeError, match="schema is missing table"):
        risk_worker.validate_risk_schema()
