from copy import deepcopy

from app.analysis.windows_event_extractor import (
    WindowsFailedLogonEvidence,
    extract_windows_failed_logon,
    is_windows_failed_logon,
)


def real_shape_local_failed_logon():
    """
    Structurally mirrors the real Event 4625 observed from the
    fresh Windows endpoint. User/SID values are sanitized.
    """

    return {
        "Task": 12544,
        "Level": 0,
        "Channel": "Security",
        "EventID": 4625,
        "Computer": "DESKTOP-TEST",
        "ProviderName": "Microsoft-Windows-Security-Auditing",
        "EventRecordID": 4541000,
        "Message": (
            "An account failed to log on.\r\n\r\n"
            "Logon Type:\t\t\t2\r\n\r\n"
            "Account For Which Logon Failed:\r\n"
            "\tSecurity ID:\t\tS-1-0-0\r\n"
            "\tAccount Name:\t\ttestuser\r\n"
            "\tAccount Domain:\t\tDESKTOP-TEST\r\n\r\n"
            "Failure Information:\r\n"
            "\tFailure Reason:\t\tUnknown user name or bad password.\r\n"
            "\tStatus:\t\t\t0xC000006E\r\n"
            "\tSub Status:\t\t0xC000006E\r\n\r\n"
            "Process Information:\r\n"
            "\tCaller Process Name:\tC:\\Program Files\\Browser\\browser.exe\r\n\r\n"
            "Network Information:\r\n"
            "\tWorkstation Name:\tDESKTOP-TEST\r\n"
            "\tSource Network Address:\t-\r\n"
            "\tSource Port:\t\t-\r\n"
        ),
        "StringInserts": [
            "S-1-5-21-TEST",
            "requestor",
            "DESKTOP-TEST",
            "0x1234",
            "S-1-0-0",
            "testuser",
            "DESKTOP-TEST",
            "0xc000006e",
            "%%2313",
            "0xc000006e",
            2,
            "Advapi",
            "Negotiate",
            "DESKTOP-TEST",
            "-",
            "-",
            0,
            "0xa3d0",
            "C:\\Program Files\\Browser\\browser.exe",
            "-",
            "-",
        ],
    }


def test_real_shape_local_4625_extracts_expected_evidence():
    record = real_shape_local_failed_logon()

    evidence = extract_windows_failed_logon(record)

    assert evidence == WindowsFailedLogonEvidence(
        target_user="testuser",
        target_domain="DESKTOP-TEST",
        source_ip=None,
        source_port=None,
        logon_type=2,
        status="0xc000006e",
        substatus="0xc000006e",
        process_name=(
            "C:\\Program Files\\Browser\\browser.exe"
        ),
        workstation_name="DESKTOP-TEST",
    )


def test_remote_4625_extracts_valid_source_ip_and_port():
    record = real_shape_local_failed_logon()
    record["StringInserts"][19] = "192.0.2.55"
    record["StringInserts"][20] = "55123"
    record["StringInserts"][10] = 3

    evidence = extract_windows_failed_logon(record)

    assert evidence is not None
    assert evidence.source_ip == "192.0.2.55"
    assert evidence.source_port == 55123
    assert evidence.logon_type == 3


def test_event_id_alone_does_not_make_failed_logon():
    record = {
        "EventID": 4625,
        "Channel": "Application",
        "ProviderName": "Microsoft-Windows-EventSystem",
        "Message": "Unrelated application event",
    }

    assert is_windows_failed_logon(record) is False
    assert extract_windows_failed_logon(record) is None


def test_wrong_security_provider_is_rejected():
    record = real_shape_local_failed_logon()
    record["ProviderName"] = "Some-Other-Provider"

    assert extract_windows_failed_logon(record) is None


def test_message_fallback_extracts_evidence_without_inserts():
    record = real_shape_local_failed_logon()
    record.pop("StringInserts")

    record["Message"] = (
        "An account failed to log on.\r\n"
        "Logon Type: 3\r\n"
        "Account For Which Logon Failed:\r\n"
        "Account Name: remoteuser\r\n"
        "Account Domain: LAB\r\n"
        "Failure Information:\r\n"
        "Status: 0xC000006D\r\n"
        "Sub Status: 0xC000006A\r\n"
        "Caller Process Name: C:\\Windows\\System32\\winlogon.exe\r\n"
        "Workstation Name: CLIENT01\r\n"
        "Source Network Address: 198.51.100.20\r\n"
        "Source Port: 51322\r\n"
    )

    evidence = extract_windows_failed_logon(record)

    assert evidence is not None
    assert evidence.target_user == "remoteuser"
    assert evidence.target_domain == "LAB"
    assert evidence.source_ip == "198.51.100.20"
    assert evidence.source_port == 51322
    assert evidence.logon_type == 3
    assert evidence.status == "0xC000006D"
    assert evidence.substatus == "0xC000006A"


def test_invalid_or_placeholder_network_values_become_none():
    record = real_shape_local_failed_logon()
    record["StringInserts"][19] = "not-an-ip"
    record["StringInserts"][20] = "not-a-port"

    evidence = extract_windows_failed_logon(record)

    assert evidence is not None
    assert evidence.source_ip is None
    assert evidence.source_port is None


def test_extractor_does_not_mutate_raw_record():
    record = real_shape_local_failed_logon()
    original = deepcopy(record)

    extract_windows_failed_logon(record)

    assert record == original
