from app.linux_normalizer import normalize_linux_event
from app.schemas.event import SecurityEvent


def sample_linux_record():
    return {
        "_HOSTNAME": "linux-agent",
        "_BOOT_ID": "11111111111111111111111111111111",
        "_SOURCE_REALTIME_TIMESTAMP": "1793960000000000",
        "_SYSTEMD_UNIT": "ssh.service",
        "_PID": "1234",
        "MESSAGE": "Failed password for invalid user admin from 192.0.2.25 port 55221 ssh2",
        "CUSTOM_EVIDENCE": "retain-me",
    }


def test_linux_event_normalization():
    record = sample_linux_record()

    result = normalize_linux_event(record)
    event = SecurityEvent.model_validate(result)

    assert event.source == "linux_journald"
    assert event.hostname == "linux-agent"
    assert event.event_type == "linux_ssh_event"


def test_linux_raw_event_is_preserved():
    record = sample_linux_record()

    result = normalize_linux_event(record)
    event = SecurityEvent.model_validate(result)

    assert event.raw_event == record
    assert event.raw_event["_BOOT_ID"] == record["_BOOT_ID"]
    assert event.raw_event["CUSTOM_EVIDENCE"] == "retain-me"
