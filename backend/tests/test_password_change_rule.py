from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.analysis.password_change_rule import (
    RULE_ID, detect_password_change_attempt,
)

WHEN = datetime(2026, 11, 9, 13, 0, tzinfo=timezone.utc)


def event(*, event_id=4723, channel="Security",
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
                "S-1-5-21-1-2-3-500", "actor", "LAB", "0x123",
            ],
        },
    }


def test_4723_detection_preserves_original_evidence_and_identity():
    record = event()
    raw_before = {**record["raw_event"],
                  "StringInserts": list(record["raw_event"]["StringInserts"])}
    result = detect_password_change_attempt(record)
    assert result.rule_id == RULE_ID
    assert result.rule_name == "Windows User Password Change Attempt"
    assert result.severity == "medium"
    assert result.target_user == "LAB\\testuser"
    assert result.device_id == record["device_id"]
    assert result.event_ids == (record["event_id"],)
    assert result.event_count == 1
    assert result.source_ip is None
    assert result.logon_type is None
    assert record["raw_event"] == raw_before


@pytest.mark.parametrize("changes", [
    {"EventID": 4724}, {"EventID": 4625}, {"EventID": "bad"},
    {"Channel": "Application"}, {"ProviderName": "Untrusted"},
])
def test_non_matching_events_rejected(changes):
    record = event()
    record["raw_event"].update(changes)
    assert detect_password_change_attempt(record) is None


@pytest.mark.parametrize("target", ["", "-", "HOST$"])
def test_invalid_target_rejected(target):
    record = event()
    record["raw_event"]["StringInserts"][0] = target
    assert detect_password_change_attempt(record) is None


def test_missing_domain_does_not_fabricate_one():
    record = event()
    record["raw_event"]["StringInserts"][1] = "-"
    assert detect_password_change_attempt(record).target_user == "testuser"


def test_subject_is_not_mistaken_for_target():
    record = event()
    record["raw_event"]["StringInserts"][4] = "different_actor"
    assert detect_password_change_attempt(record).target_user == "LAB\\testuser"


def test_incomplete_or_untrusted_evidence_rejected():
    record = event()
    record["raw_event"]["StringInserts"] = ["testuser"]
    assert detect_password_change_attempt(record) is None
    record = event()
    record["device_id"] = ""
    assert detect_password_change_attempt(record) is None
    record = event()
    record["event_time"] = datetime(2026, 11, 9)
    assert detect_password_change_attempt(record) is None
    record = event()
    record["raw_event"] = None
    assert detect_password_change_attempt(record) is None
