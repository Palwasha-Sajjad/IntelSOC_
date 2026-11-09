"""Focused unit coverage for the 4625 -> 4624 detection candidate only."""
from datetime import datetime, timedelta, timezone

from app.analysis.failed_then_success_rule import (
    RULE_ID,
    correlate_failed_then_successful_logins,
)

START = datetime(2026, 11, 10, 0, 0, tzinfo=timezone.utc)
DEVICE = "device-alpha"


def record(number, seconds, *, user="analyst", domain="LAB",
           ip="-", kind=2, device=DEVICE, provider=None):
    inserts = ["-"] * (27 if number == 4624 else 21)
    if number == 4624:
        inserts[5], inserts[6], inserts[8], inserts[18] = (
            user, domain, str(kind), ip
        )
    else:
        inserts[5], inserts[6], inserts[10], inserts[19] = (
            user, domain, str(kind), ip
        )
    return {
        "event_id": f"{number}-{seconds}-{user}-{device}",
        "device_id": device,
        "event_time": START + timedelta(seconds=seconds),
        "raw_event": {
            "EventID": number,
            "Channel": "Security",
            "ProviderName": provider or "Microsoft-Windows-Security-Auditing",
            "StringInserts": inserts,
        },
    }


def burst(*, kind=2, ip="-", user="analyst", domain="LAB", device=DEVICE):
    return [
        record(4625, i * 20, user=user, domain=domain, ip=ip,
               kind=kind, device=device)
        for i in range(5)
    ]


def test_local_burst_followed_by_success_preserves_evidence():
    events = burst() + [record(4624, 110)]
    output = correlate_failed_then_successful_logins(reversed(events))
    assert len(output) == 1
    item = output[0]
    assert item.rule_id == RULE_ID
    assert item.severity == "high"
    assert item.device_id == DEVICE
    assert item.target_user == "LAB\\analyst"
    assert item.event_count == 6
    assert item.event_ids[-1] == events[-1]["event_id"]
    assert set(item.event_ids[:-1]) == {e["event_id"] for e in events[:-1]}


def test_remote_source_must_match_exactly():
    events = burst(kind=3, ip="192.0.2.9")
    assert correlate_failed_then_successful_logins(
        events + [record(4624, 110, kind=3, ip="192.0.2.10")]
    ) == []
    item = correlate_failed_then_successful_logins(
        events + [record(4624, 110, kind=3, ip="192.0.2.9")]
    )[0]
    assert item.source_ip == "192.0.2.9"


def test_missing_remote_ip_never_correlates():
    assert correlate_failed_then_successful_logins(
        burst(kind=3) + [record(4624, 110, kind=3)]
    ) == []


def test_other_accounts_domains_devices_and_types_never_correlate():
    for successful in (
        record(4624, 110, user="different"),
        record(4624, 110, domain="OTHER"),
        record(4624, 110, device="device-beta"),
        record(4624, 110, kind=11),
    ):
        assert correlate_failed_then_successful_logins(
            burst() + [successful]
        ) == []


def test_service_logons_and_machine_accounts_are_ignored():
    assert correlate_failed_then_successful_logins(
        burst(kind=5) + [record(4624, 110, kind=5)]
    ) == []
    assert correlate_failed_then_successful_logins(
        burst(user="SYSTEM", domain="NT AUTHORITY")
        + [record(4624, 110, user="SYSTEM", domain="NT AUTHORITY")]
    ) == []
    assert correlate_failed_then_successful_logins(
        burst(user="MACHINE$") + [record(4624, 110, user="MACHINE$")]
    ) == []


def test_stale_failures_or_success_before_failures_are_ignored():
    assert correlate_failed_then_successful_logins(
        burst() + [record(4624, 400)]
    ) == []
    assert correlate_failed_then_successful_logins(
        burst() + [record(4624, -1)]
    ) == []
    assert correlate_failed_then_successful_logins(
        burst() + [record(4624, 80)]
    ) == []  # Ambiguous equal timestamp is not sufficient.


def test_duplicate_evidence_does_not_reach_threshold():
    failures = burst()[:4]
    assert correlate_failed_then_successful_logins(
        failures + [failures[0]] + [record(4624, 110)]
    ) == []


def test_one_burst_generates_one_candidate_despite_multiple_successes():
    result = correlate_failed_then_successful_logins(
        burst() + [record(4624, 110), record(4624, 130)]
    )
    assert len(result) == 1


def test_spoofed_provider_and_remote_address_local_login_are_ignored():
    events = burst()
    bad = record(4624, 110, provider="Untrusted-Provider")
    assert correlate_failed_then_successful_logins(events + [bad]) == []
    assert correlate_failed_then_successful_logins(
        events + [record(4624, 110, ip="192.0.2.9")]
    ) == []


def test_invalid_settings():
    import pytest
    with pytest.raises(ValueError):
        correlate_failed_then_successful_logins([], threshold=1)
    with pytest.raises(ValueError):
        correlate_failed_then_successful_logins([], window=timedelta(0))
