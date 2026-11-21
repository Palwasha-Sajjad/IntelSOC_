"""Dependency-free adapter tests; no checkpoint, database, or network needed."""

import unittest

from lanobert_v02.event_scoring_adapter import (
    is_eligible_event,
    score_security_event,
)


class EventScoringAdapterTests(unittest.TestCase):
    def setUp(self):
        self.calls = []

        def fake_scorer(_, text, *, max_masks, batch_size):
            self.calls.append((text, max_masks, batch_size))
            return {"score": 3.25, "positions_scored": 4,
                    "total_words": 8, "windows": 2}

        self.score_fn = fake_scorer

    def score(self, source="linux_audit", event_type="linux_process_audit_event", message="type=EXECVE a0=echo"):
        return score_security_event(
            object(), source=source, event_type=event_type,
            message=message, score_fn=self.score_fn
        )

    def test_expected_windows_and_linux_categories(self):
        expected = [
            ("windows_eventlog", "windows_security_event"),
            ("windows_eventlog", "windows_application_event"),
            ("windows_eventlog", "windows_system_event"),
            ("windows_eventlog", "windows_microsoft-windows-powershell/operational_event"),
            ("linux_journald", "linux_ssh_event"),
            ("linux_journald", "linux_sudo_event"),
            ("linux_audit", "linux_account_audit_event"),
            ("linux_audit", "linux_process_audit_event"),
        ]
        for source, event_type in expected:
            with self.subTest(source=source, event_type=event_type):
                self.assertTrue(is_eligible_event(source, event_type))

    def test_skip_test_sources_without_model_call(self):
        for source in ("intelsoc-test", "windows", "linux_vm_manual_test"):
            self.assertEqual(self.score(source=source)["status"], "skipped")
        self.assertFalse(self.calls)

    def test_skip_unapproved_event_type(self):
        self.assertEqual(self.score(event_type="unknown")["status"], "skipped")
        self.assertFalse(self.calls)

    def test_advisory_result_no_verdict_or_log_text(self):
        result = self.score()
        self.assertEqual(result["anomaly_score"], 3.25)
        self.assertEqual(result["status"], "processed")
        self.assertEqual(result["details"]["windows"], 2)
        self.assertGreaterEqual(result["latency_ms"], 0)
        self.assertNotIn("verdict", result)
        self.assertNotIn("risk_score", result)
        self.assertNotIn("message", result)
        self.assertEqual(self.calls[0][1:], (16, 16))

    def test_empty_and_oversize_messages_rejected(self):
        for message in ("", " \t ", "x" * 65537):
            with self.subTest(length=len(message)), self.assertRaises(ValueError):
                self.score(message=message)

    def test_scoring_errors_are_sanitized(self):
        def raise_error(*args, **kwargs):
            raise RuntimeError("sensitive ssh fail user=private")
        result = score_security_event(object(), source="linux_journald",
                                     event_type="linux_ssh_event", message="ssh fail",
                                     score_fn=raise_error)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["reason"], "inference_error")
        self.assertNotIn("ssh fail", str(result))
        self.assertNotIn("private", str(result))

    def test_bad_score_values_rejected(self):
        for value in (float("nan"), float("inf"), -1.0, "error", True):
            def invalid(*args, **kwargs):
                return {"score": value, "positions_scored": 1,
                        "total_words": 1, "windows": 1}
            with self.subTest(value=value):
                result = score_security_event(object(), source="linux_journald",
                                             event_type="linux_ssh_event", message="ssh fail",
                                             score_fn=invalid)
                self.assertEqual(result["status"], "failed")
                self.assertNotIn("anomaly_score", result)

    def test_bad_mask_limits_rejected(self):
        for invalid in (0, -1, True, 1.5):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                score_security_event(object(), source="linux_journald",
                                     event_type="linux_ssh_event", message="ssh fail",
                                     max_masks=invalid, score_fn=self.score_fn)

    def test_realistic_windows_and_linux_text_passed_unchanged(self):
        cases = [
            ("windows_eventlog", "windows_security_event",
             "EventID=4688 Provider=Microsoft-Windows-Security-Auditing: "
             "A new process has been created. New Process Name: C:\\Windows\\System32\\cmd.exe "
             "Process Command Line: cmd /c whoami " * 100),
            ("windows_eventlog", "windows_microsoft-windows-powershell/operational_event",
             "EventID=4104 Provider=Microsoft-Windows-PowerShell: ScriptBlockText=Get-Process"),
            ("linux_journald", "linux_ssh_event",
             "Failed password for invalid user tester from 192.0.2.4 port 2222 ssh2"),
            ("linux_journald", "linux_sudo_event",
             "sudo: tester : TTY=pts/0 ; PWD=/home/tester ; COMMAND=/usr/bin/id"),
            ("linux_audit", "linux_process_audit_event",
             'type=EXECVE msg=audit(123:456): argc=2 a0="/bin/sh" a1="-c"'),
            ("linux_audit", "linux_account_audit_event",
             'type=ADD_USER msg=audit(123:457): op=adding user acct="tester" res=success'),
        ]
        for source, event_type, message in cases:
            with self.subTest(source=source, event_type=event_type):
                result = self.score(source=source, event_type=event_type, message=message)
                self.assertEqual(result["status"], "processed")
                self.assertEqual(self.calls[-1][0], message)
                self.assertNotIn("message", result)

    def test_non_string_message_and_limits_rejected(self):
        for message in (None, 123, [], {}):
            with self.subTest(message=message), self.assertRaises(ValueError):
                self.score(message=message)
        for invalid in (0, -1, True, 1.5):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                score_security_event(object(), source="linux_journald",
                                     event_type="linux_ssh_event", message="ssh fail",
                                     batch_size=invalid, score_fn=self.score_fn)

    def test_broken_scorer_shapes_do_not_escape(self):
        for invalid in (None, [], {}, {"score": 1, "positions_scored": 0,
                                        "total_words": 1, "windows": 1}):
            def broken(*args, **kwargs):
                return invalid
            with self.subTest(invalid=invalid):
                result = score_security_event(object(), source="linux_journald",
                                             event_type="linux_ssh_event", message="ssh fail",
                                             score_fn=broken)
                self.assertEqual(result["status"], "failed")

    def test_adapter_has_no_database_or_alert_dependency(self):
        import inspect
        import lanobert_v02.event_scoring_adapter as adapter
        code = inspect.getsource(adapter)
        for forbidden in ("import psycopg", "import redis", "INSERT INTO",
                          "UPDATE security_alerts", "alert_ai_evidence", "risk_score ="):
            self.assertNotIn(forbidden, code)


if __name__ == "__main__":
    unittest.main()
