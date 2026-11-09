from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.analysis.account_lifecycle_rule import (
    RULE_ID, detect_account_lifecycle,
)

WHEN = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)


def event(*, event_id=4720, channel="Security",
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
                "newuser", "LAB", "S-1-5-21-1-2-3-1005",
                "S-1-5-21-1-2-3-500", "administrator", "LAB",
                "0x123",
            ],
        },
    }


@pytest.mark.parametrize("number,title", [
    (4720, "Windows User Account Created"),
    (4722, "Windows User Account Enabled"),
])
def test_account_change_detected_with_original_evidence(number, title):
    record = event(event_id=number)
    original = record["raw_event"].copy()
    candidate = detect_account_lifecycle(record)
    assert candidate.rule_id == RULE_ID
    assert candidate.rule_name == title
    assert candidate.severity == "medium"
    assert candidate.target_user == "LAB\\newuser"
    assert candidate.event_ids == (record["event_id"],)
    assert candidate.event_count == 1
    assert candidate.device_id == record["device_id"]
    assert candidate.source_ip is None
    assert candidate.logon_type is None
    assert record["raw_event"] == original


@pytest.mark.parametrize("changes", [
    {"EventID": 4624},
    {"EventID": 4723},
    {"EventID": "invalid"},
    {"Channel": "Application"},
    {"ProviderName": "Fake-Provider"},
])
def test_wrong_event_provenance_not_detected(changes):
    record = event()
    record["raw_event"].update(changes)
    assert detect_account_lifecycle(record) is None


@pytest.mark.parametrize("target", ["", "-", "HOST$"])
def test_invalid_or_computer_account_target_not_detected(target):
    record = event()
    record["raw_event"]["StringInserts"][0] = target
    assert detect_account_lifecycle(record) is None


def test_missing_fields_not_fabricated():
    record = event(event_id=4722)
    record["raw_event"]["StringInserts"][1] = "-"
    candidate = detect_account_lifecycle(record)
    assert candidate.target_user == "newuser"
    record["raw_event"]["StringInserts"] = []
    assert detect_account_lifecycle(record) is None


def test_missing_device_time_and_raw_evidence_rejected():
    record = event()
    record["device_id"] = None
    assert detect_account_lifecycle(record) is None
    record = event()
    record["event_time"] = datetime(2026, 11, 9)
    assert detect_account_lifecycle(record) is None
    record = event()
    record["raw_event"] = None
    assert detect_account_lifecycle(record) is None
