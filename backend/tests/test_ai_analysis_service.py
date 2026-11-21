"""Batch 5 query isolation tests using a fake connection and cursor."""
from datetime import datetime, timezone
from uuid import uuid4

from app.services import ai_analysis_service as service


class Cursor:
    def __init__(self, rows):
        self.rows = rows
        self.statements = []
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def execute(self, sql, params=None): self.statements.append((sql, params))
    def fetchall(self): return self.rows


class Connection:
    def __init__(self, cursor): self.cur = cursor
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def cursor(self): return self.cur


def test_read_only_query_and_no_sensitive_fields(monkeypatch):
    now = datetime.now(timezone.utc)
    cursor = Cursor([(uuid4(), "LAnoBERT-v0.2", "processed", 2.0, 25.0, now,
                      "LAB", "linux_journald", "linux_ssh_event")])
    monkeypatch.setattr(service.psycopg, "connect", lambda **kwargs: Connection(cursor))
    rows = service.list_ai_analysis(limit=1)
    assert len(rows) == 1
    assert rows[0]["anomaly_score"] == 2.0
    assert "message" not in rows[0] and "last_error" not in rows[0]
    assert cursor.statements[0] == ("SET TRANSACTION READ ONLY", None)
    statement, params = cursor.statements[1]
    assert params == ("LAnoBERT-v0.2", 1)
    assert "SELECT" in statement and "LIMIT %s" in statement
    assert "e.message" not in statement and "a.details" not in statement
    assert "a.last_error" not in statement
    assert "INSERT " not in statement and "UPDATE " not in statement and "DELETE " not in statement


def test_service_invalid_limit_fails_before_db(monkeypatch):
    monkeypatch.setattr(service.psycopg, "connect", lambda **kwargs: (_ for _ in ()).throw(AssertionError("DB called")))
    for number in (0, 51, True):
        try:
            service.list_ai_analysis(limit=number)
        except ValueError:
            pass
        else:
            raise AssertionError("expected ValueError")
