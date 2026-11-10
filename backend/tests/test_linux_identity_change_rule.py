from datetime import datetime, timezone

import pytest

from app.analysis.linux_identity_change_rule import (
    RULE_ID,
    detect_linux_identity_change,
)


NOW = datetime(2026, 11, 10, 16, 30, tzinfo=timezone.utc)


def audit_event(
    raw_line: str,
    *,
    event_type: str = "linux_account_audit_event",
    device_id: str = "linux-device-1",
):
    return {
        "event_id": "00000000-0000-0000-0000-000000000401",
        "device_id": device_id,
        "event_time": NOW,
        "src_ip": None,
        "message": raw_line,
        "raw_event": {
            "log": raw_line,
            "path": "/var/log/audit/audit.log",
        },
        "event_type": event_type,
    }


@pytest.mark.parametrize(
    "record_type,severity",
    [
        ("ADD_USER", "high"),
        ("DEL_USER", "high"),
        ("USER_MGMT", "medium"),
        ("ADD_GROUP", "high"),
        ("DEL_GROUP", "high"),
        ("GRP_MGMT", "medium"),
    ],
)
def test_supported_successful_account_group_records_detected(
    record_type,
    severity,
):
    event = audit_event(
        f'type={record_type} msg=audit(1794328200.123:456): '
        'pid=1234 uid=0 auid=1000 acct="testsubject" res=success'
    )

    candidate = detect_linux_identity_change(event)

    assert candidate is not None
    assert candidate.rule_id == RULE_ID
    assert candidate.severity == severity
    assert candidate.device_id == "linux-device-1"
    assert candidate.target_user == "testsubject"
    assert candidate.source_ip is None
    assert candidate.event_count == 1
    assert candidate.grouping_basis == "device_audit_type_account"


def test_failed_account_change_is_not_detected():
    event = audit_event(
        'type=ADD_USER msg=audit(1794328200.123:456): '
        'pid=1234 uid=0 auid=1000 acct="testsubject" res=failed'
    )
    assert detect_linux_identity_change(event) is None


def test_successful_keyed_identity_file_syscall_detected():
    event = audit_event(
        'type=SYSCALL msg=audit(1794328201.456:700): '
        'arch=c000003e syscall=257 success=yes exit=3 '
        'uid=0 auid=1000 comm="nano" exe="/usr/bin/nano" '
        'key="intelsoc_identity_change"',
        event_type="linux_process_audit_event",
    )

    candidate = detect_linux_identity_change(event)

    assert candidate is not None
    assert candidate.rule_id == RULE_ID
    assert candidate.severity == "high"
    assert candidate.target_user == "auid:1000"
    assert candidate.grouping_basis == "device_user_identity_file_change"


def test_failed_keyed_syscall_is_ignored():
    event = audit_event(
        'type=SYSCALL msg=audit(1794328201.456:700): '
        'arch=c000003e syscall=257 success=no exit=-13 '
        'uid=0 auid=1000 key="intelsoc_identity_change"',
        event_type="linux_process_audit_event",
    )
    assert detect_linux_identity_change(event) is None


@pytest.mark.parametrize(
    "key",
    [
        "other_key",
        "intelsoc_identity_change_extra",
        "",
    ],
)
def test_unapproved_syscall_keys_are_ignored(key):
    key_field = f' key="{key}"' if key else ""
    event = audit_event(
        'type=SYSCALL msg=audit(1794328201.456:700): '
        'arch=c000003e syscall=257 success=yes exit=3 '
        f'uid=0 auid=1000{key_field}',
        event_type="linux_process_audit_event",
    )
    assert detect_linux_identity_change(event) is None


def test_execve_is_never_accepted_by_lin004():
    event = audit_event(
        'type=EXECVE msg=audit(1794328201.456:700): '
        'argc=1 a0="/usr/sbin/useradd"',
        event_type="linux_process_audit_event",
    )
    assert detect_linux_identity_change(event) is None


def test_missing_account_name_still_preserves_event_as_change():
    event = audit_event(
        'type=USER_MGMT msg=audit(1794328200.123:456): '
        'pid=1234 uid=0 auid=1000 res=success'
    )
    candidate = detect_linux_identity_change(event)
    assert candidate is not None
    assert candidate.target_user is None
    assert candidate.grouping_basis == "device_audit_type"


def test_unset_auid_falls_back_to_uid_for_identity_file_change():
    event = audit_event(
        'type=SYSCALL msg=audit(1794328201.456:700): '
        'success=yes uid=0 auid=4294967295 '
        'key="intelsoc_identity_change"',
        event_type="linux_process_audit_event",
    )
    candidate = detect_linux_identity_change(event)
    assert candidate is not None
    assert candidate.target_user == "uid:0"


def test_malformed_or_untrusted_event_shape_is_ignored():
    event = audit_event(
        'type=ADD_USER msg=audit(1794328200.123:456): '
        'acct="testsubject" res=success'
    )
    event["device_id"] = ""
    assert detect_linux_identity_change(event) is None

    event = audit_event(
        'type=ADD_USER msg=audit(1794328200.123:456): '
        'acct="testsubject" res=success'
    )
    event["event_time"] = NOW.replace(tzinfo=None)
    assert detect_linux_identity_change(event) is None

    event = audit_event("not-an-audit-record")
    assert detect_linux_identity_change(event) is None


def test_native_ubuntu_add_user_record_is_detected():
    event = audit_event(
        'type=ADD_USER msg=audit(1794324376.841:992): '
        'pid=2933 uid=0 auid=1000 ses=28 subj=unconfined '
        'msg=\'op=adding home directory id=1001 exe="/usr/sbin/useradd" '
        'hostname=intelsoc-linux-agent addr=? terminal=pts/0 res=success\''
        'UID="root" AUID="socadmin" ID="intelsoc_l4user"'
    )
    candidate = detect_linux_identity_change(event)
    assert candidate is not None
    assert candidate.severity == "high"
    assert candidate.target_user == "intelsoc_l4user"


def test_native_ubuntu_group_record_uses_id_subject():
    event = audit_event(
        'type=ADD_GROUP msg=audit(1794324376.663:975): '
        'pid=2925 uid=0 auid=1000 ses=28 subj=unconfined '
        'msg=\'op=adding group to /etc/group id=1001 exe="/usr/sbin/groupadd" '
        'hostname=intelsoc-linux-agent addr=? terminal=pts/0 res=success\''
        'UID="root" AUID="socadmin" ID="intelsoc_l4grp"'
    )
    candidate = detect_linux_identity_change(event)
    assert candidate is not None
    assert candidate.target_user == "intelsoc_l4grp"


def test_native_ubuntu_failed_record_is_ignored():
    event = audit_event(
        'type=DEL_USER msg=audit(1794324377.028:1017): '
        'pid=2952 uid=0 auid=1000 '
        'msg=\'op=deleting user entries res=failed\''
        'UID="root" AUID="socadmin" ID="intelsoc_l4user"'
    )
    assert detect_linux_identity_change(event) is None
