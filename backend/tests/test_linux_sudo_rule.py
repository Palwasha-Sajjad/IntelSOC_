from datetime import datetime, timezone

from app.analysis.linux_sudo_rule import (
    RULE_ID,
    detect_suspicious_sudo,
)


NOW = datetime(2026, 11, 10, 16, 0, tzinfo=timezone.utc)


def sudo_event(
    message: str,
    *,
    src_ip=None,
    raw_ip=None,
    device_id="linux-device-1",
):
    raw = {
        "_HOSTNAME": "linux-agent",
        "_BOOT_ID": "boot-1",
        "_SOURCE_REALTIME_TIMESTAMP": "1794326400000000",
        "_COMM": "sudo",
        "SYSLOG_IDENTIFIER": "sudo",
        "MESSAGE": message,
    }
    if raw_ip is not None:
        raw["_REMOTE_ADDR"] = raw_ip
    return {
        "event_id": "00000000-0000-0000-0000-000000000301",
        "device_id": device_id,
        "event_time": NOW,
        "src_ip": src_ip,
        "message": message,
        "raw_event": raw,
    }


def test_local_successful_sudo_is_benign():
    event = sudo_event(
        "socadmin : TTY=pts/0 ; PWD=/home/socadmin ; "
        "USER=root ; COMMAND=/usr/bin/id"
    )
    assert detect_suspicious_sudo(event) is None


def test_remote_sudo_with_original_ip_evidence_is_detected():
    event = sudo_event(
        "socadmin : TTY=pts/0 ; PWD=/home/socadmin ; "
        "USER=root ; COMMAND=/usr/bin/id",
        src_ip="198.51.100.77",
        raw_ip="198.51.100.77",
    )
    candidate = detect_suspicious_sudo(event)
    assert candidate is not None
    assert candidate.rule_id == "RULE-LIN-005"
    assert candidate.rule_id == RULE_ID
    assert candidate.severity == "medium"
    assert candidate.target_user == "socadmin"
    assert candidate.source_ip == "198.51.100.77"
    assert candidate.grouping_basis == "device_source_ip_user"
    assert candidate.event_count == 1


def test_remote_ipv6_is_canonicalized():
    event = sudo_event(
        "socadmin : TTY=pts/0 ; PWD=/home/socadmin ; "
        "USER=root ; COMMAND=/usr/bin/id",
        src_ip="2001:0db8::10",
        raw_ip="2001:db8::10",
    )
    candidate = detect_suspicious_sudo(event)
    assert candidate is not None
    assert candidate.source_ip == "2001:db8::10"


def test_spoofed_normalized_ip_without_raw_evidence_is_rejected():
    event = sudo_event(
        "socadmin : TTY=pts/0 ; PWD=/home/socadmin ; "
        "USER=root ; COMMAND=/usr/bin/id",
        src_ip="198.51.100.77",
    )
    assert detect_suspicious_sudo(event) is None


def test_mismatched_normalized_and_raw_ip_is_rejected():
    event = sudo_event(
        "socadmin : TTY=pts/0 ; PWD=/home/socadmin ; "
        "USER=root ; COMMAND=/usr/bin/id",
        src_ip="198.51.100.77",
        raw_ip="198.51.100.78",
    )
    assert detect_suspicious_sudo(event) is None


def test_local_not_in_sudoers_is_high_severity():
    candidate = detect_suspicious_sudo(
        sudo_event(
            "guest : user NOT in sudoers ; TTY=pts/0 ; "
            "PWD=/home/guest ; USER=root ; COMMAND=/usr/bin/id"
        )
    )
    assert candidate is not None
    assert candidate.severity == "high"
    assert candidate.target_user == "guest"
    assert candidate.source_ip is None
    assert candidate.grouping_basis == "device_user_sudo_failure"


def test_local_authentication_failure_is_high_severity():
    candidate = detect_suspicious_sudo(
        sudo_event(
            "pam_unix(sudo:auth): authentication failure; "
            "logname= uid=1000 euid=0 tty=/dev/pts/0 "
            "ruser=alice rhost= user=alice"
        )
    )
    assert candidate is not None
    assert candidate.severity == "high"
    assert candidate.target_user == "alice"
    assert candidate.source_ip is None


def test_remote_failure_is_high_severity_and_keeps_ip():
    candidate = detect_suspicious_sudo(
        sudo_event(
            "pam_unix(sudo:auth): authentication failure; "
            "logname= uid=1000 euid=0 tty=/dev/pts/0 "
            "ruser=alice rhost=203.0.113.8 user=alice",
            src_ip="203.0.113.8",
        )
    )
    assert candidate is not None
    assert candidate.severity == "high"
    assert candidate.source_ip == "203.0.113.8"
    assert candidate.target_user == "alice"


def test_non_sudo_record_is_ignored():
    event = sudo_event(
        "socadmin : TTY=pts/0 ; PWD=/home/socadmin ; "
        "USER=root ; COMMAND=/usr/bin/id"
    )
    event["raw_event"]["SYSLOG_IDENTIFIER"] = "cron"
    event["raw_event"]["_COMM"] = "cron"
    assert detect_suspicious_sudo(event) is None


def test_missing_device_or_timezone_is_ignored():
    event = sudo_event(
        "guest : user NOT in sudoers ; TTY=pts/0 ; "
        "PWD=/home/guest ; USER=root ; COMMAND=/usr/bin/id"
    )
    event["device_id"] = ""
    assert detect_suspicious_sudo(event) is None

    event = sudo_event(
        "guest : user NOT in sudoers ; TTY=pts/0 ; "
        "PWD=/home/guest ; USER=root ; COMMAND=/usr/bin/id"
    )
    event["event_time"] = NOW.replace(tzinfo=None)
    assert detect_suspicious_sudo(event) is None
