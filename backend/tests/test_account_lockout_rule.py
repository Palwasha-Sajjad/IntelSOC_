from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.analysis.account_lockout_rule import (
    RULE_ID, detect_account_lockout,
)

WHEN = datetime(2026, 11, 9, 13, 0, tzinfo=timezone.utc)


def event(*, event_id=4740, channel="Security",
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
                "lockeduser", "LAB", "S-1-5-21-1-2-3-1001",
                "S-1-5-21-1-2-3-500", "administrator", "LAB",
                "0x123", "CLIENT-01",
            ],
        },
    }


def test_lockout_creates_candidate_preserving_evidence():
    record = event()
    original = record["raw_event"].copy()
    candidate = detect_account_lockout(record)
    assert candidate.rule_id == RULE_ID
    assert candidate.rule_name == "Windows User Account Locked Out"
    assert candidate.severity == "medium"
    assert candidate.target_user == "LAB\\lockeduser"
    assert candidate.device_id == record["device_id"]
    assert candidate.event_ids == (record["event_id"],)
    assert candidate.event_count == 1
    assert candidate.source_ip is None
    assert candidate.logon_type is None
    assert record["raw_event"] == original


@pytest.mark.parametrize("changes", [
    {"EventID": 4625}, {"EventID": 4725},
    {"EventID": "invalid"}, {"Channel": "Application"},
    {"ProviderName": "Untrusted-Provider"},
])
def test_unsupported_event_or_provenance_rejected(changes):
    record = event()
    record["raw_event"].update(changes)
    assert detect_account_lockout(record) is None


@pytest.mark.parametrize("name", ["", "-", "WORKSTATION$"])
def test_no_valid_user_target_rejected(name):
    record = event()
    record["raw_event"]["StringInserts"][0] = name
    assert detect_account_lockout(record) is None


def test_missing_domain_never_fabricates_one():
    record = event()
    record["raw_event"]["StringInserts"][1] = "-"
    assert detect_account_lockout(record).target_user == "lockeduser"


def test_caller_computer_not_mistaken_for_target_account():
    record = event()
    record["raw_event"]["StringInserts"][7] = "UNTRUSTED-CALLER"
    assert detect_account_lockout(record).target_user == "LAB\\lockeduser"


def test_missing_identity_time_and_evidence_rejected():
    record = event()
    record["device_id"] = None
    assert detect_account_lockout(record) is None
    record = event()
    record["event_time"] = datetime(2026, 11, 9)
    assert detect_account_lockout(record) is None
    record = event()
    record["raw_event"]["StringInserts"] = ["lockeduser"]
    assert detect_account_lockout(record) is None
    record = event()
    record["raw_event"] = None
    assert detect_account_lockout(record) is None
