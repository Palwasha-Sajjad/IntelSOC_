"""Focused WIN-009 tests with Windows event XML-shaped task evidence."""
from copy import deepcopy
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.analysis.scheduled_task_rule import (
    RULE_ID, detect_suspicious_scheduled_task,
)

NOW = datetime(2026, 11, 10, 2, 0, tzinfo=timezone.utc)
NS = "http://schemas.microsoft.com/windows/2004/02/mit/task"


def task_xml(command, args="", *, extra=""):
    return (
        f'<Task xmlns="{NS}" version="1.2"><Actions>'
        f'<Exec><Command>{command}</Command>'
        f'<Arguments>{args}</Arguments></Exec>'
        f'</Actions>{extra}</Task>'
    )


def event(*, number=4698, command="powershell.exe",
          args="-EncodedCommand SQBFAFgA", xml=None,
          task_name=r"\IntelSOC-Demo", provider="Microsoft-Windows-Security-Auditing"):
    inserts = [
        "S-1-5-21-1-2-3-500", "operator", "LAB",
        "0x124", task_name,
        xml if xml is not None else task_xml(command, args),
    ]
    return {
        "event_id": str(uuid4()),
        "device_id": str(uuid4()),
        "event_time": NOW,
        "raw_event": {
            "EventID": number,
            "Channel": "Security",
            "ProviderName": provider,
            "StringInserts": inserts,
        },
    }


@pytest.mark.parametrize("number", [4698, 4702])
def test_encoded_powershell_creation_and_update_detect(number):
    source = event(number=number)
    snapshot = deepcopy(source)
    candidate = detect_suspicious_scheduled_task(source)
    assert candidate is not None
    assert candidate.rule_id == RULE_ID
    assert candidate.severity == "high"
    assert candidate.device_id == source["device_id"]
    assert candidate.event_ids == (source["event_id"],)
    assert candidate.event_count == 1
    assert source == snapshot


def test_mshta_remote_script_detect():
    found = detect_suspicious_scheduled_task(
        event(command=r"C:\Windows\System32\mshta.exe",
              args="https://example.invalid/task.hta")
    )
    assert found is not None


@pytest.mark.parametrize("command,args", [
    ("notepad.exe", "notes.txt"),
    ("powershell.exe", "-File C:\\Scripts\\backup.ps1"),
    ("cmd.exe", "/c echo hello"),
    ("mshta.exe", r"C:\\Tools\\local.hta"),
])
def test_benign_task_execution_is_ignored(command, args):
    assert detect_suspicious_scheduled_task(
        event(command=command, args=args)
    ) is None


def test_suspicious_string_in_registration_metadata_not_an_exec_action():
    xml = (
        f'<Task xmlns="{NS}"><RegistrationInfo>'
        '<Description>-EncodedCommand</Description>'
        '</RegistrationInfo><Actions>'
        '<Exec><Command>notepad.exe</Command></Exec>'
        '</Actions></Task>'
    )
    assert detect_suspicious_scheduled_task(event(xml=xml)) is None


@pytest.mark.parametrize("number", [4699, 4700, 4701, 4624])
def test_other_security_event_ids_ignored(number):
    assert detect_suspicious_scheduled_task(event(number=number)) is None


def test_invalid_provider_channel_task_name_and_xml_ignored():
    cases = [
        event(provider="Untrusted"),
        event(task_name="relative-task"),
        event(xml="<Task>"),
        event(xml='<!DOCTYPE Task [<!ENTITY x "y">]><Task/>'),
        event(xml="<Task><Actions/></Task>"),
    ]
    item = event()
    item["raw_event"]["Channel"] = "Application"
    cases.append(item)
    for item in cases:
        assert detect_suspicious_scheduled_task(item) is None


def test_invalid_identity_and_event_time_ignored():
    item = event()
    item["device_id"] = None
    assert detect_suspicious_scheduled_task(item) is None
    item = event()
    item["event_time"] = datetime(2026, 11, 10)
    assert detect_suspicious_scheduled_task(item) is None


def test_multiple_exec_actions_second_suspicious_detected():
    xml = (
        f'<Task xmlns="{NS}"><Actions>'
        '<Exec><Command>notepad.exe</Command></Exec>'
        '<Exec><Command>pwsh.exe</Command>'
        '<Arguments>-enc SQBFAFgA</Arguments></Exec>'
        '</Actions></Task>'
    )
    assert detect_suspicious_scheduled_task(event(xml=xml)) is not None


def test_exec_tag_outside_actions_is_not_task_execution():
    xml = (
        f'<Task xmlns="{NS}"><RegistrationInfo>'
        '<Exec><Command>powershell.exe</Command>'
        '<Arguments>-EncodedCommand SQBFAFgA</Arguments></Exec>'
        '</RegistrationInfo><Actions>'
        '<Exec><Command>notepad.exe</Command></Exec>'
        '</Actions></Task>'
    )
    assert detect_suspicious_scheduled_task(event(xml=xml)) is None


def test_task_action_requires_direct_exec_child():
    xml = (
        f'<Task xmlns="{NS}"><Actions>'
        '<ComHandler><Exec><Command>powershell.exe</Command>'
        '<Arguments>-enc SQBFAFgA</Arguments></Exec></ComHandler>'
        '</Actions></Task>'
    )
    assert detect_suspicious_scheduled_task(event(xml=xml)) is None
