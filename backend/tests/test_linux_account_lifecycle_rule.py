from datetime import datetime, timezone

import pytest

from app.analysis.linux_account_lifecycle_rule import (
    RULE_ID,
    detect_linux_account_lifecycle,
)


NOW = datetime(2026, 11, 10, 18, 0, tzinfo=timezone.utc)


def audit_event(raw_line: str, *, device_id="linux-device-1"):
    return {
        "event_id": "00000000-0000-0000-0000-000000000331",
        "device_id": device_id,
        "event_time": NOW,
        "src_ip": None,
        "message": raw_line,
        "raw_event": {
            "log": raw_line,
            "path": "/var/log/audit/audit.log",
        },
        "event_type": "linux_account_audit_event",
    }


@pytest.mark.parametrize(
    "record_type,severity",
    [
        ("ADD_USER", "high"),
        ("DEL_USER", "high"),
        ("USER_MGMT", "medium"),
    ],
)
def test_supported_account_lifecycle_detected(record_type, severity):
    candidate = detect_linux_account_lifecycle(
        audit_event(
            f'type={record_type} msg=audit(1794333600.123:500): '
            'pid=1234 uid=0 auid=1000 acct="testuser" res=success'
        )
    )

    assert candidate is not None
    assert candidate.rule_id == "RULE-LIN-003"
    assert candidate.rule_id == RULE_ID
    assert candidate.severity == severity
    assert candidate.target_user == "testuser"
    assert candidate.device_id == "linux-device-1"
    assert candidate.event_count == 1


def test_native_ubuntu_add_user_uses_id_subject():
    candidate = detect_linux_account_lifecycle(
        audit_event(
            'type=ADD_USER msg=audit(1794333600.123:501): '
            'pid=1234 uid=0 auid=1000 '
            'msg=\'op=adding user id=1001 exe="/usr/sbin/useradd" '
            'hostname=agent res=success\''
            'UID="root" AUID="socadmin" ID="newuser"'
        )
    )

    assert candidate is not None
    assert candidate.target_user == "newuser"


def test_failed_account_change_is_benign():
    event = audit_event(
        'type=ADD_USER msg=audit(1794333600.123:502): '
        'acct="newuser" res=failed'
    )
    assert detect_linux_account_lifecycle(event) is None


@pytest.mark.parametrize(
    "record_type",
    ["ADD_GROUP", "DEL_GROUP", "GRP_MGMT"],
)
def test_group_record_types_are_not_owned_by_lin003(record_type):
    event = audit_event(
        f'type={record_type} msg=audit(1794333600.123:503): '
        'acct="sudo" res=success'
    )
    assert detect_linux_account_lifecycle(event) is None


def test_user_mgmt_with_explicit_group_is_left_to_lin004():
    event = audit_event(
        'type=USER_MGMT msg=audit(1794333600.123:504): '
        'acct="alice" grp="sudo" res=success'
    )
    assert detect_linux_account_lifecycle(event) is None


def test_generic_identity_syscall_does_not_alert_without_account_semantics():
    event = audit_event(
        'type=SYSCALL msg=audit(1794333600.123:505): '
        'success=yes auid=1000 uid=0 key="intelsoc_identity_change"'
    )
    event["event_type"] = "linux_process_audit_event"

    assert detect_linux_account_lifecycle(event) is None


def test_missing_subject_is_supported_without_inventing_identity():
    candidate = detect_linux_account_lifecycle(
        audit_event(
            'type=USER_MGMT msg=audit(1794333600.123:506): '
            'pid=1234 uid=0 auid=1000 res=success'
        )
    )

    assert candidate is not None
    assert candidate.target_user is None
    assert candidate.grouping_basis == "device_account_change"


def test_malformed_or_untrusted_event_is_ignored():
    event = audit_event(
        'type=ADD_USER msg=audit(1794333600.123:507): '
        'acct="newuser" res=success',
        device_id="",
    )
    assert detect_linux_account_lifecycle(event) is None

    event = audit_event("not-an-audit-record")
    assert detect_linux_account_lifecycle(event) is None

    event = audit_event(
        'type=DEL_USER msg=audit(1794333600.123:508): '
        'acct="olduser" res=success'
    )
    event["event_time"] = NOW.replace(tzinfo=None)
    assert detect_linux_account_lifecycle(event) is None


def test_user_mgmt_group_operation_without_grp_field_is_left_to_lin004():
    event = audit_event(
        'type=USER_MGMT msg=audit(1794333600.123:509): '
        'acct="alice" '
        'msg=\'op=add-shadow-group acct="alice" res=success\''
        'ID="sudo"'
    )
    assert detect_linux_account_lifecycle(event) is None
