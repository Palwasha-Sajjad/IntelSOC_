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


def sample_sudo_record():
    return {
        "_HOSTNAME": "linux-agent",
        "_BOOT_ID": "11111111111111111111111111111111",
        "_SOURCE_REALTIME_TIMESTAMP": "1793961000000000",
        "_COMM": "sudo",
        "SYSLOG_IDENTIFIER": "sudo",
        "_PID": "4321",
        "MESSAGE": (
            "socadmin : TTY=pts/0 ; PWD=/home/socadmin ; "
            "USER=root ; COMMAND=/usr/bin/id"
        ),
        "CUSTOM_EVIDENCE": "sudo-retain-me",
    }


def test_linux_sudo_event_normalization():
    record = sample_sudo_record()

    result = normalize_linux_event(record)
    event = SecurityEvent.model_validate(result)

    assert event.source == "linux_journald"
    assert event.hostname == "linux-agent"
    assert event.event_type == "linux_sudo_event"
    assert event.message == record["MESSAGE"]


def test_linux_sudo_raw_event_is_preserved():
    record = sample_sudo_record()

    result = normalize_linux_event(record)
    event = SecurityEvent.model_validate(result)

    assert event.raw_event == record
    assert event.raw_event["SYSLOG_IDENTIFIER"] == "sudo"
    assert event.raw_event["CUSTOM_EVIDENCE"] == (
        "sudo-retain-me"
    )


def test_unknown_linux_source_is_rejected():
    record = sample_linux_record()

    record["_SYSTEMD_UNIT"] = "cron.service"

    try:
        normalize_linux_event(record)

    except ValueError as error:
        assert "Unsupported Linux journal event source" in str(error)

    else:
        raise AssertionError(
            "Unsupported Linux source was accepted"
        )
