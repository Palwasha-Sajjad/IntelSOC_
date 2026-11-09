"""WIN-011 fragment reconstruction, provenance and benign guards."""
from copy import deepcopy
from datetime import datetime, timezone
from uuid import uuid4

from app.analysis.script_block_rule import (
    RULE_ID, detect_suspicious_script_block, is_complete_script_block,
)

NOW = datetime(2026, 11, 10, tzinfo=timezone.utc)


def event(part, total, text, *, block=None, device=None):
    return {
        "event_id": str(uuid4()),
        "device_id": device or "device-a",
        "event_time": NOW,
        "raw_event": {
            "EventID": 4104,
            "Channel": "Microsoft-Windows-PowerShell/Operational",
            "ProviderName": "Microsoft-Windows-PowerShell",
            "StringInserts": [
                str(part), str(total), text, block or "block-a", "",
            ],
        },
    }


def test_single_part_encoded_dynamic_execution():
    item = event(1, 1, "IEX ([Convert]::FromBase64String('SQBFAFgA'))")
    candidate = detect_suspicious_script_block([item])
    assert candidate and candidate.rule_id == RULE_ID
    assert candidate.event_ids == (item["event_id"],)


def test_multifragment_reassembles_across_boundary_and_links_all():
    a = event(1, 2, "Invoke-Ex", block="multi")
    b = event(2, 2, "pression ([Convert]::FromBase64String('QQ=='))", block="multi")
    untouched = deepcopy([a, b])
    assert is_complete_script_block([b, a])
    candidate = detect_suspicious_script_block([b, a])
    assert candidate is not None
    assert candidate.event_ids == (a["event_id"], b["event_id"])
    assert candidate.event_count == 2
    assert [a, b] == untouched


def test_incomplete_and_duplicate_part_never_processed():
    a = event(1, 2, "IEX ([Convert]::FromBase64String('QQ=='))")
    assert not is_complete_script_block([a])
    assert detect_suspicious_script_block([a]) is None
    b = event(1, 2, "same", block="block-a")
    assert not is_complete_script_block([a, b])
    assert detect_suspicious_script_block([a, b]) is None


def test_cross_device_and_cross_script_blocks_not_combined():
    a = event(1, 2, "IEX (", device="host-a")
    b = event(2, 2, "[Convert]::FromBase64String('QQ=='))", device="host-b")
    assert not is_complete_script_block([a, b])
    b["device_id"] = "host-a"
    b["raw_event"]["StringInserts"][3] = "other-id"
    assert not is_complete_script_block([a, b])


def test_benign_script_not_detected():
    a = event(1, 1, "Get-Process | Select-Object Name")
    assert is_complete_script_block([a])
    assert detect_suspicious_script_block([a]) is None


def test_invalid_provider_and_missing_identity_rejected():
    a = event(1, 1, "IEX ([Convert]::FromBase64String('QQ=='))")
    a["raw_event"]["ProviderName"] = "Unknown"
    assert not is_complete_script_block([a])
    a["raw_event"]["ProviderName"] = "Microsoft-Windows-PowerShell"
    a["device_id"] = ""
    assert not is_complete_script_block([a])
