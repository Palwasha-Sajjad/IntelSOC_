from datetime import datetime, timezone
from uuid import uuid4

from app.analysis.security_log_cleared_rule import (
    RULE_ID, detect_security_log_cleared,
)

TIME = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)


def event(*, channel="Security", provider="Microsoft-Windows-Eventlog",
          event_id=1102, device_id=None):
    return {
        "event_id": str(uuid4()),
        "device_id": device_id if device_id is not None else str(uuid4()),
        "event_time": TIME,
        "raw_event": {
            "EventID": event_id, "Channel": channel,
            "ProviderName": provider,
            "StringInserts": ["S-1-5-18", "operator", "LAB", "0x123"],
            "Message": "The audit log was cleared.",
        },
    }


def test_genuine_security_log_clear_creates_one_evidence_candidate():
    record = event()
    original_raw = dict(record["raw_event"])
    candidate = detect_security_log_cleared(record)
    assert candidate.rule_id == RULE_ID
    assert candidate.rule_name == "Windows Security Audit Log Cleared"
    assert candidate.severity == "high"
    assert candidate.event_ids == (record["event_id"],)
    assert candidate.event_count == 1
    assert candidate.device_id == record["device_id"]
    assert candidate.target_user == "operator"
    assert candidate.source_ip is None
    assert candidate.logon_type is None
    assert record["raw_event"] == original_raw


def test_missing_actor_is_not_fabricated():
    record = event()
    record["raw_event"]["StringInserts"] = []
    assert detect_security_log_cleared(record).target_user is None


def test_wrong_event_provider_or_channel_rejected():
    assert detect_security_log_cleared(event(event_id=4625)) is None
    assert detect_security_log_cleared(event(channel="Application")) is None
    assert detect_security_log_cleared(event(provider="Other")) is None
    assert detect_security_log_cleared(event(event_id="not-number")) is None
    assert detect_security_log_cleared(event(device_id="")) is None


def test_invalid_time_or_raw_payload_rejected():
    record = event()
    record["event_time"] = datetime(2026, 11, 9)
    assert detect_security_log_cleared(record) is None
    record = event()
    record["raw_event"] = None
    assert detect_security_log_cleared(record) is None
