from datetime import datetime, timedelta, timezone

import pytest

from app.analysis.linux_ssh_bruteforce_rule import (
    DEFAULT_WINDOW,
    RULE_ID,
    evaluate_ssh_bruteforce,
)


BASE = datetime(2026, 11, 10, 10, 0, tzinfo=timezone.utc)


def ssh_failure(
    index: int,
    *,
    device_id: str = "linux-device-1",
    user: str = "alice",
    source_ip: str = "192.0.2.25",
    event_time: datetime | None = None,
    message: str | None = None,
):
    event_time = event_time or BASE + timedelta(seconds=index * 30)
    message = message or (
        f"Failed password for {user} from {source_ip} "
        f"port {40000 + index} ssh2"
    )
    return {
        "event_id": f"00000000-0000-0000-0000-{index:012d}",
        "device_id": device_id,
        "event_time": event_time,
        "src_ip": source_ip,
        "message": message,
        "raw_event": {
            "_SYSTEMD_UNIT": "ssh.service",
            "MESSAGE": message,
        },
    }


def test_lin001_detects_five_failures_in_five_minutes():
    candidates = evaluate_ssh_bruteforce(
        [ssh_failure(index) for index in range(5)]
    )

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.rule_id == RULE_ID
    assert candidate.device_id == "linux-device-1"
    assert candidate.target_user == "alice"
    assert candidate.source_ip == "192.0.2.25"
    assert candidate.event_count == 5
    assert len(candidate.event_ids) == 5
    assert candidate.grouping_basis == "device_source_ip_user"


def test_lin001_below_threshold_is_benign():
    assert evaluate_ssh_bruteforce(
        [ssh_failure(index) for index in range(4)]
    ) == []


def test_lin001_does_not_mix_source_ips():
    events = [
        ssh_failure(0, source_ip="192.0.2.25"),
        ssh_failure(1, source_ip="192.0.2.25"),
        ssh_failure(2, source_ip="192.0.2.25"),
        ssh_failure(3, source_ip="192.0.2.25"),
        ssh_failure(4, source_ip="192.0.2.26"),
    ]
    assert evaluate_ssh_bruteforce(events) == []


def test_lin001_does_not_mix_devices():
    events = [
        ssh_failure(index, device_id="linux-device-1")
        for index in range(4)
    ]
    events.append(
        ssh_failure(4, device_id="linux-device-2")
    )
    assert evaluate_ssh_bruteforce(events) == []


def test_lin001_does_not_mix_users():
    events = [
        ssh_failure(index, user="alice")
        for index in range(4)
    ]
    events.append(ssh_failure(4, user="bob"))
    assert evaluate_ssh_bruteforce(events) == []


def test_lin001_supports_ipv6():
    candidates = evaluate_ssh_bruteforce([
        ssh_failure(index, source_ip="2001:db8::10")
        for index in range(5)
    ])
    assert len(candidates) == 1
    assert candidates[0].source_ip == "2001:db8::10"


def test_lin001_requires_normalized_source_ip():
    events = [ssh_failure(index) for index in range(5)]
    for event in events:
        event["src_ip"] = None
    assert evaluate_ssh_bruteforce(events) == []


def test_lin001_rejects_source_ip_mismatch_with_raw_evidence():
    events = [ssh_failure(index) for index in range(5)]
    for event in events:
        event["src_ip"] = "192.0.2.99"
    assert evaluate_ssh_bruteforce(events) == []


def test_lin001_ignores_non_failure_ssh_chatter():
    events = [
        ssh_failure(
            index,
            message=(
                "Invalid user alice from 192.0.2.25 "
                f"port {40000 + index}"
            ),
        )
        for index in range(5)
    ]
    assert evaluate_ssh_bruteforce(events) == []


def test_lin001_deduplicates_replayed_event_ids():
    events = [ssh_failure(index) for index in range(4)]
    events.append(events[-1].copy())
    assert evaluate_ssh_bruteforce(events) == []


def test_lin001_respects_time_window():
    events = [
        ssh_failure(
            index,
            event_time=BASE + timedelta(minutes=index * 2),
        )
        for index in range(5)
    ]
    assert evaluate_ssh_bruteforce(events) == []


def test_lin001_emits_one_candidate_per_continuous_episode():
    events = [ssh_failure(index) for index in range(8)]
    candidates = evaluate_ssh_bruteforce(events)
    assert len(candidates) == 1
    assert candidates[0].event_count == 5


@pytest.mark.parametrize(
    "threshold,window",
    [
        (1, DEFAULT_WINDOW),
        (5, timedelta(0)),
    ],
)
def test_lin001_rejects_invalid_configuration(threshold, window):
    with pytest.raises(ValueError):
        evaluate_ssh_bruteforce(
            [ssh_failure(0)],
            threshold=threshold,
            window=window,
        )
