"""Batch 6: SQL isolation and empty-dataset semantics (fake DB)."""
from datetime import datetime, timezone

import pytest

from app.services import ai_analysis_service as service


class Cursor:
    def __init__(self, row):
        self.row = row
        self.commands = []
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def execute(self, sql, args=None): self.commands.append((sql, args))
    def fetchone(self): return self.row


class Connection:
    def __init__(self, cursor): self.cur = cursor
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def cursor(self): return self.cur


def test_aggregate_query_is_read_only_and_model_scoped(monkeypatch):
    stamp = datetime(2026, 11, 21, tzinfo=timezone.utc)
    cursor = Cursor((8, 5, 2, 1, 12.5, stamp))
    monkeypatch.setattr(service.psycopg, "connect", lambda **kwargs: Connection(cursor))
    item = service.summarize_ai_analysis()
    assert item == {"model_version": "LAnoBERT-v0.2", "total": 8,
                    "processed": 5, "failed": 2, "skipped": 1,
                    "average_latency_ms": 12.5, "last_processed_at": stamp}
    assert cursor.commands[0] == ("SET TRANSACTION READ ONLY", None)
    sql, params = cursor.commands[1]
    assert params == ("LAnoBERT-v0.2",)
    assert "WHERE model_version = %s" in sql
    assert "AVG(latency_ms) FILTER (WHERE status = 'processed')" in sql
    assert "event_ai_analysis" in sql
    for forbidden in ("e.message", "anomaly_score", "alert_ai_evidence", "INSERT ", "UPDATE ", "DELETE "):
        assert forbidden not in sql


def test_empty_data_has_zero_counts_and_null_metrics(monkeypatch):
    cursor = Cursor((0, 0, 0, 0, None, None))
    monkeypatch.setattr(service.psycopg, "connect", lambda **kwargs: Connection(cursor))
    result = service.summarize_ai_analysis()
    assert result["total"] == 0
    assert result["average_latency_ms"] is None
    assert result["last_processed_at"] is None


def test_wrong_model_does_not_query_database(monkeypatch):
    monkeypatch.setattr(service.psycopg, "connect", lambda **kwargs: (_ for _ in ()).throw(AssertionError("database contacted")))
    with pytest.raises(ValueError):
        service.summarize_ai_analysis(model_version="other-model")
