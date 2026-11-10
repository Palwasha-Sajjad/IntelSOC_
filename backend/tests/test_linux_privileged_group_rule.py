from datetime import datetime, timezone

import pytest

from app.analysis.linux_privileged_group_rule import (
    PRIVILEGED_GROUPS,
    RULE_ID,
    detect_linux_privileged_group_change,
)


NOW = datetime(2026, 11, 10, 18, 10, tzinfo=timezone.utc)


def audit_event(raw_line: str, *, device_id="linux-device-1"):
    return {
        "event_id": "00000000-0000-0000-0000-000000000341",
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
    "record_type",
    ["ADD_GROUP", "DEL_GROUP", "GRP_MGMT"],
)
def test_privileged_group_change_is_detected(record_type):
    candidate = detect_linux_privileged_group_change(
        audit_event(
            f'type={record_type} msg=audit(1794334200.123:600): '
            'acct="sudo" res=success'
        )
    )

    assert candidate is not None
    assert candidate.rule_id == "RULE-LIN-004"
    assert candidate.rule_id == RULE_ID
    assert candidate.severity == "high"
    assert candidate.grouping_basis == "device_privileged_group:sudo"


def test_native_ubuntu_privileged_group_id_is_detected():
    candidate = detect_linux_privileged_group_change(
        audit_event(
            'type=ADD_GROUP msg=audit(1794334200.123:601): '
            'pid=1234 uid=0 auid=1000 '
            'msg=\'op=adding group to /etc/group id=27 '
            'exe="/usr/sbin/groupadd" res=success\''
            'UID="root" AUID="socadmin" ID="sudo"'
        )
    )

    assert candidate is not None
    assert candidate.target_user == "sudo"


def test_privileged_membership_user_mgmt_is_detected():
    candidate = detect_linux_privileged_group_change(
        audit_event(
            'type=USER_MGMT msg=audit(1794334200.123:602): '
            'acct="alice" grp="sudo" res=success'
        )
    )

    assert candidate is not None
    assert candidate.target_user == "alice"
    assert candidate.grouping_basis == "device_privileged_group:sudo"


@pytest.mark.parametrize(
    "group",
    ["developers", "students", "project_team", "intelsoc_l4grp"],
)
def test_ordinary_group_changes_do_not_alert(group):
    event = audit_event(
        'type=GRP_MGMT msg=audit(1794334200.123:603): '
        f'acct="{group}" res=success'
    )
    assert detect_linux_privileged_group_change(event) is None


def test_user_mgmt_for_ordinary_group_does_not_alert():
    event = audit_event(
        'type=USER_MGMT msg=audit(1794334200.123:604): '
        'acct="alice" grp="developers" res=success'
    )
    assert detect_linux_privileged_group_change(event) is None


def test_missing_group_identity_does_not_alert():
    event = audit_event(
        'type=GRP_MGMT msg=audit(1794334200.123:605): '
        'uid=0 auid=1000 res=success'
    )
    assert detect_linux_privileged_group_change(event) is None


def test_failed_privileged_group_change_does_not_alert():
    event = audit_event(
        'type=GRP_MGMT msg=audit(1794334200.123:606): '
        'acct="sudo" res=failed'
    )
    assert detect_linux_privileged_group_change(event) is None


def test_non_group_account_change_is_ignored():
    event = audit_event(
        'type=ADD_USER msg=audit(1794334200.123:607): '
        'acct="sudo" res=success'
    )
    assert detect_linux_privileged_group_change(event) is None


def test_device_identity_is_preserved():
    candidate = detect_linux_privileged_group_change(
        audit_event(
            'type=GRP_MGMT msg=audit(1794334200.123:608): '
            'acct="docker" res=success',
            device_id="linux-device-2",
        )
    )

    assert candidate is not None
    assert candidate.device_id == "linux-device-2"


def test_privileged_group_allowlist_is_explicit():
    assert "sudo" in PRIVILEGED_GROUPS
    assert "docker" in PRIVILEGED_GROUPS
    assert "developers" not in PRIVILEGED_GROUPS
