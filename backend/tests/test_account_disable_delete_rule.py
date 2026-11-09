from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.analysis.account_disable_delete_rule import (
    RULE_ID, detect_account_disable_or_delete,
)

WHEN = datetime(2026, 11, 9, 13, 0, tzinfo=timezone.utc)


def event(*, event_id=4725, channel="Security",
          provider="Microsoft-Windows-Security-Auditing"):
    return {
        "event_id": str(uuid4()),
        "device_id": str(uuid4()),
        "event_time": WHEN,
        "raw_event": {
            "EventID": event_id,
            "Channel": channel,
            "ProviderName": provider,
            "StringInserts": [
                "testuser", "LAB", "S-1-5-21-1-2-3-1001",
                "S-1-5-21-1-2-3-500", "administrator", "LAB", "0x123",
            ],
        },
    }


@pytest.mark.parametrize("event_id,title", [
    (4725, "Windows User Account Disabled"),
    (4726, "Windows User Account Deleted"),
])
def test_account_disable_or_delete_creates_candidate(event_id, title):
    record = event(event_id=event_id)
    raw_before = record["raw_event"].copy()
    candidate = detect_account_disable_or_delete(record)
    assert candidate.rule_id == RULE_ID
    assert candidate.rule_name == title
    assert candidate.severity == "medium"
    assert candidate.target_user == "LAB\\testuser"
    assert candidate.device_id == record["device_id"]
    assert candidate.event_ids == (record["event_id"],)
    assert candidate.event_count == 1
    assert candidate.source_ip is None
    assert candidate.logon_type is None
    assert record["raw_event"] == raw_before


@pytest.mark.parametrize("changes", [
    {"EventID": 4720},
    {"EventID": 4722},
    {"EventID": 4625},
    {"EventID": "bad"},
    {"Channel": "Application"},
    {"ProviderName": "Untrusted-Provider"},
])
def test_wrong_event_or_provenance_rejected(changes):
    record = event()
    record["raw_event"].update(changes)
    assert detect_account_disable_or_delete(record) is None


@pytest.mark.parametrize("target", ["", "-", "DESKTOP$"])
def test_missing_user_or_computer_account_not_detected(target):
    record = event()
    record["raw_event"]["StringInserts"][0] = target
    assert detect_account_disable_or_delete(record) is None


def test_missing_domain_does_not_fabricate_identity():
    record = event()
    record["raw_event"]["StringInserts"][1] = "-"
    candidate = detect_account_disable_or_delete(record)
    assert candidate.target_user == "testuser"


def test_short_inserts_missing_device_or_utc_timestamp_rejected():
    record = event()
    record["raw_event"]["StringInserts"] = ["testuser"]
    assert detect_account_disable_or_delete(record) is None
    record = event()
    record["device_id"] = None
    assert detect_account_disable_or_delete(record) is None
    record = event()
    record["event_time"] = datetime(2026, 11, 9)
    assert detect_account_disable_or_delete(record) is None
    record = event()
    record["raw_event"] = None
    assert detect_account_disable_or_delete(record) is None
