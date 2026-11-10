from app.linux_src_ip import extract_linux_source_ip
from app.linux_normalizer import normalize_linux_event


def _base_record(message: str) -> dict:
    return {
        "_HOSTNAME": "linux-agent",
        "_BOOT_ID": "11111111111111111111111111111111",
        "_SOURCE_REALTIME_TIMESTAMP": "1793960000000000",
        "_SYSTEMD_UNIT": "ssh.service",
        "_PID": "1234",
        "MESSAGE": message,
    }


def test_ssh_source_ip_is_extracted_from_original_message():
    record = _base_record(
        "Failed password for invalid user admin from 192.0.2.25 port 55221 ssh2"
    )

    result = normalize_linux_event(record)

    assert result["src_ip"] == "192.0.2.25"
    assert result["raw_event"] == record


def test_ipv6_ssh_source_ip_is_canonicalized():
    record = _base_record(
        "Accepted publickey for socadmin from 2001:db8::10 port 5555 ssh2"
    )

    assert extract_linux_source_ip(record) == "2001:db8::10"


def test_sudo_source_ip_uses_evidence_field_when_present():
    record = _base_record(
        "socadmin : TTY=pts/0 ; PWD=/home/socadmin ; USER=root ; COMMAND=/usr/bin/id"
    )
    record["_SYSTEMD_UNIT"] = ""
    record["SYSLOG_IDENTIFIER"] = "sudo"
    record["_COMM"] = "sudo"
    record["_REMOTE_ADDR"] = "198.51.100.77"

    result = normalize_linux_event(record)

    assert result["event_type"] == "linux_sudo_event"
    assert result["src_ip"] == "198.51.100.77"


def test_sudo_rhost_from_message_is_extracted():
    record = _base_record(
        "pam_unix(sudo:session): session opened for user root rhost=203.0.113.8"
    )
    record["_SYSTEMD_UNIT"] = ""
    record["SYSLOG_IDENTIFIER"] = "sudo"
    record["_COMM"] = "sudo"

    assert normalize_linux_event(record)["src_ip"] == "203.0.113.8"


def test_local_sudo_without_ip_evidence_remains_none():
    record = _base_record(
        "socadmin : TTY=pts/0 ; PWD=/home/socadmin ; USER=root ; COMMAND=/usr/bin/id"
    )
    record["_SYSTEMD_UNIT"] = ""
    record["SYSLOG_IDENTIFIER"] = "sudo"
    record["_COMM"] = "sudo"

    assert normalize_linux_event(record)["src_ip"] is None


def test_invalid_or_unspecified_addresses_are_rejected():
    assert extract_linux_source_ip({"_REMOTE_ADDR": "not-an-ip"}) is None
    assert extract_linux_source_ip({"_REMOTE_ADDR": "0.0.0.0"}) is None
