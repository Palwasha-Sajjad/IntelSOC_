import pytest

from app.linux_audit_normalizer import (
    normalize_linux_audit_event,
)
from app.schemas.event import SecurityEvent


@pytest.mark.parametrize(
    "record_type",
    [
        "ADD_USER",
        "DEL_USER",
        "USER_MGMT",
        "ADD_GROUP",
        "DEL_GROUP",
        "GRP_MGMT",
    ],
)
def test_supported_account_audit_record(
    record_type,
):
    record = {
        "log": (
            f"type={record_type} "
            "msg=audit(1793962000.123:456): "
            "pid=1234 uid=0 auid=1000 "
            'acct="testuser" res=success'
        ),
        "path": "/var/log/audit/audit.log",
    }

    result = normalize_linux_audit_event(
        record,
        hostname="linux-agent",
    )

    event = SecurityEvent.model_validate(result)

    assert event.source == "linux_audit"
    assert event.hostname == "linux-agent"
    assert (
        event.event_type
        == "linux_account_audit_event"
    )

    assert event.raw_event == record
    assert f"type={record_type}" in event.message


def test_same_audit_record_has_same_id():
    record = {
        "log": (
            "type=USER_MGMT "
            "msg=audit(1793962000.123:456): "
            'acct="testuser" res=success'
        )
    }

    first = normalize_linux_audit_event(
        record,
        hostname="linux-agent",
    )

    second = normalize_linux_audit_event(
        record,
        hostname="linux-agent",
    )

    assert first["event_id"] == second["event_id"]


def test_unsupported_audit_type_is_rejected():
    record = {
        "log": (
            "type=EXECVE "
            "msg=audit(1793962000.123:456): "
            'argc=1 a0="/usr/bin/id"'
        )
    }

    with pytest.raises(
        ValueError,
        match="Unsupported Linux audit record type",
    ):
        normalize_linux_audit_event(
            record,
            hostname="linux-agent",
        )


def test_invalid_audit_record_is_rejected():
    record = {
        "log": "not-a-valid-audit-record"
    }

    with pytest.raises(
        ValueError,
        match="Invalid Linux audit record format",
    ):
        normalize_linux_audit_event(
            record,
            hostname="linux-agent",
        )


def test_hostname_comes_from_trusted_device():
    record = {
        "log": (
            "type=ADD_USER "
            "msg=audit(1793962000.123:457): "
            'acct="newuser" res=success'
        ),
        "hostname": "spoofed-host",
    }

    result = normalize_linux_audit_event(
        record,
        hostname="registered-linux-device",
    )

    assert (
        result["hostname"]
        == "registered-linux-device"
    )
