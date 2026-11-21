"""Unit tests use in-memory DB doubles; no PostgreSQL or checkpoint required."""
import unittest
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from unittest.mock import patch

from lanobert_v02 import ai_batch_worker as worker


class Cursor:
    def __init__(self, rows=()):
        self.rows = rows
        self.calls = []
        self.rowcount = 1

    def __enter__(self): return self
    def __exit__(self, *args): return False
    def execute(self, query, args=None):
        self.calls.append((query, args))
    def fetchall(self): return self.rows


class Connection:
    def __init__(self, cursor): self.cur = cursor
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def cursor(self): return self.cur


class BatchTests(unittest.TestCase):
    def setUp(self):
        self.since = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.id = uuid4()
        self.read_cursor = Cursor([(self.id, "linux_journald", "linux_ssh_event", "Failed password")])
        self.write_cursor = Cursor()
        self.issued = []
        def connect():
            n = len(self.issued)
            self.issued.append(n)
            return Connection(self.read_cursor if n == 0 else self.write_cursor)
        self.connect = connect

    def fake_result(self, *_a, **_k):
        return {"status": "processed", "anomaly_score": 2.7,
                "latency_ms": 12.0, "details": {"positions_scored": 4, "total_words": 4, "windows": 1}}

    def call(self, **kwargs):
        return worker.run_batch(since=self.since, limit=5, write_results=False,
                                model_dir=Path("unused"), connect=self.connect,
                                load_model=lambda p: object(),
                                score_event=self.fake_result, **kwargs)

    def test_default_dry_run_never_inserts(self):
        result = self.call()
        self.assertEqual((result["selected"], result["processed"], result["inserted"]), (1, 1, 0))
        self.assertTrue(result["dry_run"])
        self.assertEqual(len(self.issued), 1)
        self.assertEqual(len(self.read_cursor.calls), 2)
        self.assertEqual(self.read_cursor.calls[0][0], "SET TRANSACTION READ ONLY")

    def test_one_write_and_only_to_ai_table(self):
        result = worker.run_batch(since=self.since, limit=1, write_results=True,
                                  model_dir=Path("unused"), connect=self.connect,
                                  load_model=lambda p: object(), score_event=self.fake_result)
        self.assertEqual(result["inserted"], 1)
        self.assertEqual(len(self.write_cursor.calls), 1)
        query = self.write_cursor.calls[0][0]
        self.assertIn("INSERT INTO event_ai_analysis", query)
        self.assertIn("ON CONFLICT (event_id, model_version) DO NOTHING", query)
        self.assertNotIn("UPDATE ", query)
        self.assertNotIn("security_alerts", query)
        self.assertNotIn("alert_risk", query)

    def test_missing_records_do_not_load_model(self):
        self.read_cursor.rows = []
        result = worker.run_batch(since=self.since, limit=1, write_results=False,
                                  model_dir=Path("unused"), connect=self.connect,
                                  load_model=lambda _: self.fail("model loaded"))
        self.assertEqual(result["selected"], 0)

    def test_bad_events_fail_safely(self):
        def invalid(*args, **kwargs): raise ValueError("sensitive event text")
        result = worker.run_batch(since=self.since, limit=1, write_results=True,
                                  model_dir=Path("unused"), connect=self.connect,
                                  load_model=lambda _: object(), score_event=invalid)
        self.assertEqual(result["failed"], 1)
        params = self.write_cursor.calls[0][1]
        self.assertEqual(params[2], "failed")
        self.assertEqual(params[5], "inference_error")
        self.assertNotIn("sensitive", str(params))

    def test_limits_and_timezones(self):
        for limit in (0, -1, 21, True):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                worker.validate_limit(limit)
        for value in ("2026-01-01", "bad", "9999-01-01T00:00:00+00:00"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                worker.parse_since(value)
        self.assertEqual(worker.parse_since("2026-01-01T00:00:00Z"), self.since)

    def test_sql_source_allowlist_and_idempotence(self):
        sql = worker._SELECT_SQL
        self.assertIn("NOT EXISTS", sql)
        self.assertIn("e.received_at >= %s", sql)
        self.assertIn("e.event_type = ANY(%s)", sql)
        self.assertNotIn("raw_event", sql)
        self.assertNotIn("LIMIT 0", sql)

    def test_failing_scores_do_not_include_log_or_threshold(self):
        def fail(*args, **kwargs):
            return {"status": "failed", "reason": "inference_error", "latency_ms": 24.5}
        result = worker.run_batch(since=self.since, limit=1, write_results=True,
                                  model_dir=Path("unused"), connect=self.connect,
                                  load_model=lambda _: object(), score_event=fail)
        self.assertEqual(result["failed"], 1)
        self.assertEqual(self.write_cursor.calls[0][1][3], None)
        self.assertNotIn("risk", str(self.write_cursor.calls[0][1]))


if __name__ == "__main__":
    unittest.main()
