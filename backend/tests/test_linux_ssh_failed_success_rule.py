from datetime import datetime, timedelta, timezone

import pytest

from app.analysis.linux_ssh_failed_success_rule import (
    RULE_ID,
    WINDOW,
    correlate_ssh_failed_then_success,
)


BASE = datetime(2026, 11, 10, 10, 0, tzinfo=timezone.utc)


def ssh_event(
    index: int,
    *,
    success: bool = False,
    device_id: str = "linux-device-1",
    user: str = "alice",
    source_ip: str = "192.0.2.25",
    event_time: datetime | None = None,
    method: str = "password",
):
    event_time = event_time or BASE + timedelta(seconds=index * 30)
    outcome = "Accepted" if success else "Failed"
    message = (
        f"{outcome} {method} for {user} from {source_ip} "
        f"port {40000 + index} ssh2"
    )
    return {
        "event_id": f"00000000-0000-0000-0001-{index:012d}",
        "device_id": device_id,
        "event_time": event_time,
        "src_ip": source_ip,
        "message": message,
        "raw_event": {
            "_SYSTEMD_UNIT": "ssh.service",
            "MESSAGE": message,
        },
    }


def failure_burst(**kwargs):
    return [ssh_event(index, **kwargs) for index in range(5)]


def test_lin002_correlates_five_failures_then_success():
    failures = failure_burst()
    success = ssh_event(5, success=True)

    candidates = correlate_ssh_failed_then_success(
        [success, *reversed(failures)]
    )

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.rule_id == RULE_ID
    assert candidate.severity == "high"
    assert candidate.device_id == "linux-device-1"
    assert candidate.target_user == "alice"
    assert candidate.source_ip == "192.0.2.25"
    assert candidate.grouping_basis == "device_source_ip_user"
    assert candidate.event_count == 6
    assert candidate.event_ids[-1] == success["event_id"]
    assert set(candidate.event_ids[:-1]) == {
        event["event_id"] for event in failures
    }


def test_lin002_below_threshold_is_benign():
    events = failure_burst()[:4] + [ssh_event(5, success=True)]
    assert correlate_ssh_failed_then_success(events) == []


@pytest.mark.parametrize(
    "success",
    [
        ssh_event(5, success=True, source_ip="192.0.2.99"),
        ssh_event(5, success=True, device_id="linux-device-2"),
        ssh_event(5, success=True, user="bob"),
    ],
)
def test_lin002_requires_same_source_device_and_user(success):
    assert correlate_ssh_failed_then_success(
        failure_burst() + [success]
    ) == []


def test_lin002_linux_usernames_are_case_sensitive():
    assert correlate_ssh_failed_then_success(
        failure_burst(user="Alice")
        + [ssh_event(5, success=True, user="alice")]
    ) == []


def test_lin002_supports_ipv6_and_publickey_success():
    events = failure_burst(source_ip="2001:db8::10")
    success = ssh_event(
        5,
        success=True,
        source_ip="2001:db8::10",
        method="publickey",
    )
    candidate = correlate_ssh_failed_then_success(events + [success])[0]
    assert candidate.source_ip == "2001:db8::10"


def test_lin002_rejects_stale_failure_burst():
    failures = failure_burst()
    success = ssh_event(
        5,
        success=True,
        event_time=BASE + WINDOW + timedelta(seconds=1),
    )
    assert correlate_ssh_failed_then_success(failures + [success]) == []


def test_lin002_rejects_success_before_or_equal_to_last_failure():
    failures = failure_burst()
    before = ssh_event(
        5,
        success=True,
        event_time=BASE - timedelta(seconds=1),
    )
    equal = ssh_event(
        6,
        success=True,
        event_time=failures[-1]["event_time"],
    )
    assert correlate_ssh_failed_then_success(failures + [before]) == []
    assert correlate_ssh_failed_then_success(failures + [equal]) == []


def test_lin002_deduplicates_replayed_event_ids():
    failures = failure_burst()[:4]
    events = failures + [failures[-1].copy(), ssh_event(5, success=True)]
    assert correlate_ssh_failed_then_success(events) == []


def test_lin002_rejects_raw_and_normalized_source_ip_mismatch():
    failures = failure_burst()
    success = ssh_event(5, success=True)
    success["src_ip"] = "192.0.2.99"
    assert correlate_ssh_failed_then_success(failures + [success]) == []


def test_lin002_ignores_non_authentication_ssh_chatter():
    failures = failure_burst()
    success = ssh_event(5, success=True)
    success["message"] = "pam_unix(sshd:session): session opened for user alice"
    success["raw_event"]["MESSAGE"] = success["message"]
    assert correlate_ssh_failed_then_success(failures + [success]) == []


def test_lin002_one_burst_generates_one_candidate_for_multiple_successes():
    events = failure_burst() + [
        ssh_event(5, success=True),
        ssh_event(6, success=True),
    ]
    assert len(correlate_ssh_failed_then_success(events)) == 1


@pytest.mark.parametrize(
    "threshold,window",
    [
        (1, WINDOW),
        (5, timedelta(0)),
    ],
)
def test_lin002_rejects_invalid_configuration(threshold, window):
    with pytest.raises(ValueError):
        correlate_ssh_failed_then_success(
            [],
            threshold=threshold,
            window=window,
        )
