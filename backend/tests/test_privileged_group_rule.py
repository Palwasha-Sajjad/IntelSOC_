from datetime import datetime, timezone
from uuid import uuid4

from app.analysis.privileged_group_rule import (
    RULE_ID, detect_privileged_group_member_added,
)

TIME = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)


def event(*, sid="S-1-5-32-544", channel="Security",
          provider="Microsoft-Windows-Security-Auditing", event_id=4732):
    return {
        "event_id": str(uuid4()),
        "device_id": str(uuid4()),
        "event_time": TIME,
        "raw_event": {
            "EventID": event_id,
            "Channel": channel,
            "ProviderName": provider,
            "StringInserts": [
                "-", "S-1-5-21-1-2-3-1001",
                "Administrators", "BUILTIN", sid,
                "S-1-5-21-1-2-3-500", "admin", "LAB", "0x123", "-",
            ],
        },
    }


def test_builtin_administrators_member_added_detected():
    record = event()
    raw = record["raw_event"].copy()
    candidate = detect_privileged_group_member_added(record)
    assert candidate.rule_id == RULE_ID
    assert candidate.severity == "high"
    assert candidate.device_id == record["device_id"]
    assert candidate.target_user == "S-1-5-21-1-2-3-1001"
    assert candidate.event_ids == (record["event_id"],)
    assert candidate.event_count == 1
    assert candidate.source_ip is None
    assert record["raw_event"] == raw


def test_privileged_group_detected_even_if_group_name_is_localized():
    record = event()
    record["raw_event"]["StringInserts"][2] = "Administratoren"
    assert detect_privileged_group_member_added(record) is not None


def test_non_admin_groups_and_untrusted_provenance_rejected():
    assert detect_privileged_group_member_added(event(sid="S-1-5-32-545")) is None
    assert detect_privileged_group_member_added(event(sid="S-1-5-21-1-2-3-512")) is None
    assert detect_privileged_group_member_added(event(channel="Application")) is None
    assert detect_privileged_group_member_added(event(provider="Unknown")) is None
    assert detect_privileged_group_member_added(event(event_id=4733)) is None


def test_missing_sid_or_unverified_group_name_rejected():
    record = event()
    record["raw_event"]["StringInserts"][4] = "-"
    assert detect_privileged_group_member_added(record) is None
    record["raw_event"]["StringInserts"] = ["Administrators"]
    assert detect_privileged_group_member_added(record) is None


def test_missing_subject_is_not_fabricated():
    record = event()
    record["raw_event"]["StringInserts"][0:2] = ["-", "-"]
    candidate = detect_privileged_group_member_added(record)
    assert candidate.target_user is None


def test_missing_identity_invalid_event_time_and_raw_payload_rejected():
    record = event()
    record["device_id"] = None
    assert detect_privileged_group_member_added(record) is None
    record = event()
    record["event_time"] = datetime(2026, 11, 9)
    assert detect_privileged_group_member_added(record) is None
    record = event()
    record["raw_event"] = {}
    assert detect_privileged_group_member_added(record) is None
