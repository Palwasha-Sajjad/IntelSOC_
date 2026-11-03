import pytest

from app.schemas.event import SecurityEvent
from app.windows_normalizer import normalize_windows_event


def sample_record():
    return {
        "ProviderName": "IntelSOC-Test",
        "EventID": 777,
        "TimeCreated": "2026-11-03 17:37:46 +0500",
        "EventRecordID": 28636,
        "Channel": "Application",
        "Computer": "LAB-PC",
        "Message": "First Windows log collection test",
    }


def test_windows_event_normalization():
    result = normalize_windows_event(sample_record())

    event = SecurityEvent.model_validate(result)

    assert event.source == "windows_eventlog"
    assert event.hostname == "LAB-PC"
    assert event.event_type == "windows_application_event"
    assert event.timestamp.isoformat() == "2026-11-03T17:37:46+05:00"
    assert "EventID=777" in event.message


def test_same_event_has_same_id():
    record = sample_record()

    first = normalize_windows_event(record)
    second = normalize_windows_event(record)

    assert first["event_id"] == second["event_id"]


def test_missing_required_field():
    record = sample_record()
    del record["TimeCreated"]

    with pytest.raises(ValueError, match="TimeCreated"):
        normalize_windows_event(record)
