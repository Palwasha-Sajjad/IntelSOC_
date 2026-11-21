"""Pure unit tests for the opt-in monitor; never touch the database/model."""
import sys
import types
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

# Real ai_batch_worker imports psycopg, unavailable in lightweight test envs.
# Stub only the input validator when running these isolated unit tests.
_STUB = types.ModuleType("lanobert_v02.ai_batch_worker")
def _validate_limit(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 20:
        raise ValueError("invalid limit")
_STUB.validate_limit = _validate_limit

from lanobert_v02 import ai_monitor


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.since = datetime(2026, 11, 1, tzinfo=timezone.utc)
        self.calls = []
        self.loads = []
        self.sleeps = []
        self.messages = []

    def batch(self, **kw):
        self.calls.append(kw)
        # Simulate actual worker lazy-loading model for nonempty batches.
        kw["load_model"](kw["model_dir"])
        return {"selected": 1, "processed": 1, "failed": 0,
                "inserted": 1, "dry_run": False}

    def run_case(self, **overrides):
        kw = dict(since=self.since, limit=2, poll_seconds=2.0,
                  model_dir=Path("checkpoint"), write_results=True,
                  max_cycles=3, batch_fn=self.batch,
                  model_loader=lambda path: self.loads.append(path) or object(),
                  sleep_fn=self.sleeps.append, reporter=self.messages.append)
        kw.update(overrides)
        with patch.dict(sys.modules, {"lanobert_v02.ai_batch_worker": _STUB}):
            return ai_monitor.monitor(**kw)

    def test_three_bounded_cycles_reuse_model_once(self):
        result = self.run_case()
        self.assertEqual(result, {"cycles": 3, "processed": 3,
                                  "failed": 0, "inserted": 3})
        self.assertEqual(len(self.loads), 1)
        self.assertEqual(len(self.calls), 3)
        self.assertEqual(self.sleeps, [2.0, 2.0])
        self.assertEqual(len(self.messages), 3)
        self.assertTrue(all(c["write_results"] for c in self.calls))
        self.assertTrue(all(c["limit"] == 2 for c in self.calls))

    def test_requires_explicit_write_consent(self):
        with self.assertRaisesRegex(ValueError, "write-results"):
            self.run_case(write_results=False)
        self.assertEqual(self.calls, [])

    def test_invalid_limits_and_intervals_rejected_before_io(self):
        for limit in (0, 21, -1, True):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                self.run_case(limit=limit)
        for interval in (0, 1.99, 301, -1, True, float('nan'), float('inf')):
            with self.subTest(interval=interval), self.assertRaises(ValueError):
                self.run_case(poll_seconds=interval)
        self.assertEqual(self.calls, [])

    def test_requires_timezone_and_valid_cycles(self):
        with self.assertRaises(ValueError):
            self.run_case(since=datetime(2026, 11, 1))
        for value in (0, -1, True, 1.5):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.run_case(max_cycles=value)
        self.assertFalse(self.calls)

    def test_no_sleep_after_single_cycle(self):
        self.run_case(max_cycles=1)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.sleeps, [])

    def test_database_exception_stops_without_endless_retry(self):
        def fail(**kwargs):
            raise ConnectionError("DB unavailable")
        with self.assertRaises(ConnectionError):
            self.run_case(batch_fn=fail)
        self.assertEqual(self.sleeps, [])

    def test_invalid_counters_stop_processing(self):
        for reply in ({}, {"selected": 3, "processed": 3, "failed": 0,
                             "inserted": 3},
                      {"selected": 1, "processed": 1, "failed": 0, "inserted": 2}):
            with self.subTest(reply=reply), self.assertRaises(RuntimeError):
                self.run_case(batch_fn=lambda **kw: reply)

    def test_operator_interrupt_is_not_swallowed(self):
        def interrupt(_):
            raise KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            self.run_case(sleep_fn=interrupt)
        self.assertEqual(len(self.calls), 1)


if __name__ == "__main__":
    unittest.main()
