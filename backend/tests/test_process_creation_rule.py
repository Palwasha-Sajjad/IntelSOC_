"""WIN-010 Windows Security 4688 source and signal validation."""
from copy import deepcopy
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.analysis.process_creation_rule import (
    RULE_ID, detect_suspicious_process_creation,
)

NOW = datetime(2026, 11, 10, tzinfo=timezone.utc)


def event(*, number=4688, program=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
          command_line="powershell.exe -NoProfile -EncodedCommand SQBFAFgA",
          provider="Microsoft-Windows-Security-Auditing"):
    # Version 1/2 fields: SubjectUserSid, SubjectUserName,
    # SubjectDomainName, SubjectLogonId, NewProcessId, NewProcessName,
    # TokenElevationType, ProcessId, CommandLine (optional), ...
    return {
        "event_id": str(uuid4()),
        "device_id": str(uuid4()),
        "event_time": NOW,
        "raw_event": {
            "EventID": number,
            "Channel": "Security",
            "ProviderName": provider,
            "StringInserts": ["sid", "user", "LAB", "0x1", "0x222",
                              program, "%%1936", "0x100",
                              command_line, "S-1-16-8192", "parent.exe"],
        },
    }


@pytest.mark.parametrize("program,command", [
    (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell.exe -enc SQBFAFgA"),
    (r"C:\Program Files\PowerShell\7\pwsh.exe", "pwsh -EncodedCommand SQBFAFgA"),
    (r"C:\Windows\System32\mshta.exe", "mshta https://example.invalid/demo.hta"),
])
def test_strong_signatures_detected_without_mutating_source(program, command):
    source = event(program=program, command_line=command)
    original = deepcopy(source)
    candidate = detect_suspicious_process_creation(source)
    assert candidate is not None
    assert candidate.rule_id == RULE_ID
    assert candidate.severity == "high"
    assert candidate.device_id == source["device_id"]
    assert candidate.event_ids == (source["event_id"],)
    assert candidate.event_count == 1
    assert source == original


@pytest.mark.parametrize("program,command", [
    (r"C:\Windows\System32\notepad.exe", "notepad.exe -EncodedCommand SQBFAFgA"),
    (r"C:\Windows\System32\cmd.exe", "cmd /c echo hello"),
    (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell -File backup.ps1"),
    (r"C:\Windows\System32\mshta.exe", r"mshta C:\Tools\local.hta"),
])
def test_benign_or_unrelated_commands_ignored(program, command):
    assert detect_suspicious_process_creation(event(program=program, command_line=command)) is None


def test_missing_command_line_is_not_treated_as_malicious():
    item = event()
    item["raw_event"]["StringInserts"][8] = ""
    assert detect_suspicious_process_creation(item) is None
    item["raw_event"]["StringInserts"] = item["raw_event"]["StringInserts"][:8]
    assert detect_suspicious_process_creation(item) is None


@pytest.mark.parametrize("number", [4689, 4624, 4698])
def test_other_events_ignored(number):
    assert detect_suspicious_process_creation(event(number=number)) is None


def test_untrusted_provider_channel_and_identity_rejected():
    assert detect_suspicious_process_creation(event(provider="Fake")) is None
    item = event()
    item["raw_event"]["Channel"] = "Application"
    assert detect_suspicious_process_creation(item) is None
    item = event()
    item["device_id"] = None
    assert detect_suspicious_process_creation(item) is None
    item = event()
    item["event_time"] = datetime(2026, 11, 10)
    assert detect_suspicious_process_creation(item) is None


def test_corrupt_payload_ignored():
    item = event()
    item["raw_event"]["StringInserts"] = "not an array"
    assert detect_suspicious_process_creation(item) is None
    item = event()
    item["raw_event"]["StringInserts"][5] = None
    assert detect_suspicious_process_creation(item) is None
