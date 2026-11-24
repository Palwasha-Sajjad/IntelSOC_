from datetime import datetime, timedelta, timezone

from app.analysis.failed_login_rule import (
    RULE_ID,
    evaluate_repeated_failed_logins,
)


BASE_TIME = datetime(
    2026,
    11,
    9,
    5,
    50,
    0,
    tzinfo=timezone.utc,
)


def failed_logon_event(
    *,
    number: int,
    seconds: int,
    user: str = "PMYLS",
    source_ip: str | None = None,
    logon_type: int = 2,
    device_id: str = "529a6c54-8f61-4f94-be53-57924f1924eb",
):
    inserts = [
        "S-1-5-21-TEST",
        "requestor",
        "DESKTOP-TEST",
        "0x1234",
        "S-1-0-0",
        user,
        "DESKTOP-TEST",
        "0xc000006e",
        "%%2313",
        "0xc000006e",
        logon_type,
        "Advapi",
        "Negotiate",
        "DESKTOP-TEST",
        "-",
        "-",
        0,
        "0xa3d0",
        "C:\\Program Files\\Browser\\browser.exe",
        source_ip or "-",
        "55123" if source_ip else "-",
    ]

    return {
        "event_id": f"event-{number}",
        "device_id": device_id,
        "event_time": BASE_TIME + timedelta(seconds=seconds),
        "raw_event": {
            "Channel": "Security",
            "EventID": 4625,
            "ProviderName": "Microsoft-Windows-Security-Auditing",
            "StringInserts": inserts,
            "Message": "An account failed to log on.",
        },
    }


def test_five_local_failures_within_five_minutes_detect():
    events = [
        failed_logon_event(number=i, seconds=i * 30)
        for i in range(5)
    ]

    candidates = evaluate_repeated_failed_logins(events)

    assert len(candidates) == 1

    candidate = candidates[0]

    assert candidate.rule_id == RULE_ID
    assert candidate.severity == "medium"
    assert candidate.target_user == "PMYLS"
    assert candidate.source_ip is None
    assert candidate.logon_type == 2
    assert candidate.grouping_basis == "device_user_logon_type"
    assert candidate.event_count == 5
    assert candidate.event_ids == (
        "event-0",
        "event-1",
        "event-2",
        "event-3",
        "event-4",
    )


def test_remote_failures_group_by_source_ip():
    events = [
        failed_logon_event(
            number=i,
            seconds=i * 20,
            source_ip="192.0.2.55",
            logon_type=3,
        )
        for i in range(5)
    ]

    candidate = evaluate_repeated_failed_logins(events)[0]

    assert candidate.source_ip == "192.0.2.55"
    assert candidate.logon_type == 3
    assert candidate.grouping_basis == "device_user_source_ip"


def test_replayed_event_id_does_not_inflate_threshold():
    events = [
        failed_logon_event(number=i, seconds=i * 20)
        for i in range(4)
    ]

    events.append(events[-1])

    assert evaluate_repeated_failed_logins(events) == []


def test_same_event_id_counts_once_even_if_payload_replayed_later():
    events = [
        failed_logon_event(number=i, seconds=i * 20)
        for i in range(5)
    ]

    replay = dict(events[-1])
    replay["event_time"] = BASE_TIME + timedelta(seconds=100)

    candidates = evaluate_repeated_failed_logins(
        events + [replay]
    )

    assert len(candidates) == 1
    assert candidates[0].event_count == 5


def test_failures_outside_window_do_not_detect():
    events = [
        failed_logon_event(number=i, seconds=i * 100)
        for i in range(5)
    ]

    assert evaluate_repeated_failed_logins(events) == []


def test_different_users_are_not_combined():
    events = [
        failed_logon_event(
            number=0,
            seconds=0,
            user="alice",
        ),
        failed_logon_event(
            number=1,
            seconds=20,
            user="alice",
        ),
        failed_logon_event(
            number=2,
            seconds=40,
            user="alice",
        ),
        failed_logon_event(
            number=3,
            seconds=60,
            user="bob",
        ),
        failed_logon_event(
            number=4,
            seconds=80,
            user="bob",
        ),
    ]

    assert evaluate_repeated_failed_logins(events) == []


def test_extra_failure_in_same_burst_does_not_duplicate_candidate():
    events = [
        failed_logon_event(number=i, seconds=i * 20)
        for i in range(6)
    ]

    candidates = evaluate_repeated_failed_logins(events)

    assert len(candidates) == 1
    assert candidates[0].event_ids == (
        "event-0",
        "event-1",
        "event-2",
        "event-3",
        "event-4",
    )


def test_new_episode_after_lull_can_detect_again():
    first = [
        failed_logon_event(number=i, seconds=i * 20)
        for i in range(5)
    ]

    second = [
        failed_logon_event(
            number=10 + i,
            seconds=700 + (i * 20),
        )
        for i in range(5)
    ]

    candidates = evaluate_repeated_failed_logins(
        first + second
    )

    assert len(candidates) == 2


def test_non_security_4625_is_ignored():
    events = [
        failed_logon_event(number=i, seconds=i * 20)
        for i in range(4)
    ]

    false_positive = failed_logon_event(
        number=99,
        seconds=80,
    )
    false_positive["raw_event"] = {
        "Channel": "Application",
        "EventID": 4625,
        "ProviderName": "Microsoft-Windows-EventSystem",
        "Message": "Unrelated EventSystem record",
    }

    assert evaluate_repeated_failed_logins(
        events + [false_positive]
    ) == []


def test_different_remote_ips_are_not_combined():
    events = [
        failed_logon_event(
            number=i,
            seconds=i * 20,
            source_ip=(
                "192.0.2.55"
                if i < 3
                else "192.0.2.56"
            ),
            logon_type=3,
        )
        for i in range(5)
    ]

    assert evaluate_repeated_failed_logins(events) == []


def unknown_local_event(number, seconds, **overrides):
    options = {"user": "-", "source_ip": "127.0.0.1", "logon_type": 2}
    options.update(overrides)
    event = failed_logon_event(number=number, seconds=seconds, **options)
    event["raw_event"]["StringInserts"][7] = "0xc000006d"
    event["raw_event"]["StringInserts"][9] = "0xc0000380"
    return event


def test_unknown_local_five_failures_detect_with_nullable_user():
    events = [unknown_local_event(i, seconds) for i, seconds in enumerate((0, 3, 6, 8, 108))]
    candidates = evaluate_repeated_failed_logins(events)
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.rule_id == RULE_ID
    assert candidate.target_user is None
    assert candidate.source_ip == "127.0.0.1"
    assert candidate.logon_type == 2
    assert candidate.grouping_basis == "device_unknown_user_local_interactive"
    assert candidate.severity == "medium"
    assert candidate.event_count == 5
    assert candidate.event_ids == tuple(f"event-{i}" for i in range(5))


def test_unknown_local_four_failures_and_duplicate_do_not_detect():
    events = [unknown_local_event(i, i * 20) for i in range(4)]
    assert evaluate_repeated_failed_logins(events + [events[-1]]) == []


def test_unknown_and_known_users_are_not_combined():
    events = [unknown_local_event(i, i * 20) for i in range(3)]
    events += [unknown_local_event(i, i * 20, user="alice") for i in range(3, 5)]
    assert evaluate_repeated_failed_logins(events) == []


def test_unknown_local_failures_on_different_devices_are_not_combined():
    events = [unknown_local_event(i, i * 20, device_id=f"device-{i // 3}") for i in range(5)]
    assert evaluate_repeated_failed_logins(events) == []


def test_unknown_remote_and_noninteractive_failures_are_excluded():
    for source_ip, logon_type in [("192.0.2.55", 2), ("127.0.0.1", 3), (None, 2)]:
        events = [unknown_local_event(i, i * 20, source_ip=source_ip, logon_type=logon_type) for i in range(5)]
        assert evaluate_repeated_failed_logins(events) == []


def test_unknown_ipv6_loopback_failures_detect():
    events = [unknown_local_event(i, i * 20, source_ip="::1") for i in range(5)]
    candidate, = evaluate_repeated_failed_logins(events)
    assert candidate.source_ip == "::1"
    assert candidate.target_user is None


def test_unknown_local_failures_outside_window_do_not_detect():
    events = [unknown_local_event(i, i * 100) for i in range(5)]
    assert evaluate_repeated_failed_logins(events) == []
