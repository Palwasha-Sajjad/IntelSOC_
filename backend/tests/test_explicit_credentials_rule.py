"""WIN-012 authentic-shaped 4648 positive and false-positive guards."""
from copy import deepcopy
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.analysis.explicit_credentials_rule import (
    RULE_ID, detect_unusual_explicit_credentials,
)

NOW = datetime(2026, 11, 10, tzinfo=timezone.utc)


def event(*, process=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
          ip="192.168.1.18", actor="alice", target="administrator",
          domain="LAB", number=4648):
    # 4648: Subject SID/User/Domain/LogonId, LogonGuid, TargetUserName,
    # TargetDomainName/LogonGuid, TargetServerName/Info, ProcessId/Name, IP/Port.
    return {
        "event_id": str(uuid4()),
        "device_id": str(uuid4()),
        "event_time": NOW,
        "raw_event": {
            "EventID": number,
            "Channel": "Security",
            "ProviderName": "Microsoft-Windows-Security-Auditing",
            "StringInserts": [
                "S-1-5-21", actor, domain, "0x100", "{guid}",
                target, domain, "{guid}", "server-a", "extra",
                "0x123", process, ip, "445",
            ],
        },
    }


@pytest.mark.parametrize("process", [
    "powershell.exe",
    r"C:\Windows\System32\cmd.exe",
    r"C:\Program Files\PowerShell\7\pwsh.exe",
])
def test_shell_distinct_account_nonlocal_ip_detected(process):
    item = event(process=process)
    before = deepcopy(item)
    detection = detect_unusual_explicit_credentials(item)
    assert detection is not None
    assert detection.rule_id == RULE_ID
    assert detection.severity == "medium"
    assert detection.source_ip == "192.168.1.18"
    assert detection.target_user == "administrator"
    assert detection.device_id == item["device_id"]
    assert detection.event_ids == (item["event_id"],)
    assert item == before


@pytest.mark.parametrize("process", [
    "svchost.exe", "winlogon.exe", "lsass.exe", "wininit.exe",
])
def test_windows_system_processes_never_trigger(process):
    assert detect_unusual_explicit_credentials(event(process=process)) is None


@pytest.mark.parametrize("ip", [
    "-", "", "127.0.0.1", "::1", "0.0.0.0", "::",
    "169.254.10.1", "not-an-ip",
])
def test_no_meaningful_remote_ip_no_detection(ip):
    assert detect_unusual_explicit_credentials(event(ip=ip)) is None


def test_same_accounts_are_not_alerted():
    assert detect_unusual_explicit_credentials(
        event(actor="alice", target="ALICE")
    ) is None


def test_missing_device_and_invalid_provenance_rejected():
    item = event()
    item["device_id"] = ""
    assert detect_unusual_explicit_credentials(item) is None
    item = event()
    item["raw_event"]["ProviderName"] = "Other"
    assert detect_unusual_explicit_credentials(item) is None
    item = event(number=4624)
    assert detect_unusual_explicit_credentials(item) is None
    item = event()
    item["raw_event"]["Channel"] = "Application"
    assert detect_unusual_explicit_credentials(item) is None


def test_invalid_field_shapes_and_naive_time_rejected():
    item = event()
    item["raw_event"]["StringInserts"] = item["raw_event"]["StringInserts"][:12]
    assert detect_unusual_explicit_credentials(item) is None
    item = event()
    item["raw_event"]["StringInserts"][12] = None
    assert detect_unusual_explicit_credentials(item) is None
    item = event()
    item["event_time"] = datetime(2026, 11, 10)
    assert detect_unusual_explicit_credentials(item) is None
