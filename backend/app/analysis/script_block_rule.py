"""WIN-011: analyze complete Windows PowerShell 4104 script blocks.

A script block may span multiple authentic events. Never score partial fragments,
mix devices, or mutate raw evidence. High-confidence signatures only.
"""
from datetime import datetime
import re
from typing import Any, Mapping, Sequence

from app.analysis.detection_candidate import DetectionCandidate

RULE_ID = "RULE-WIN-011"
RULE_NAME = "Suspicious PowerShell Script Block"
CHANNEL = "microsoft-windows-powershell/operational"
PROVIDER = "microsoft-windows-powershell"
MAX_SCRIPT_CHARS = 262144
MAX_PARTS = 128

# Remote download followed by dynamic execution in one reconstructed script.
REMOTE_FETCH = re.compile(
    r"(?is)(?:\bdownloadstring\s*\(|\binvoke-webrequest\b|\biwr\b).{0,2048}?https?://"
    r"|https?://.{0,2048}?\bdownloadstring\s*\("
)
DYNAMIC_EXEC = re.compile(r"(?i)\b(?:invoke-expression|iex)\b")
BASE64_DECODE = re.compile(r"(?i)\bfrombase64string\s*\(")


def _fragment(event: Mapping[str, Any]):
    raw = event.get("raw_event")
    if not isinstance(raw, dict):
        return None
    try:
        number = int(raw.get("EventID"))
    except (ValueError, TypeError):
        return None
    if (
        number != 4104
        or str(raw.get("Channel") or "").casefold() != CHANNEL
        or str(raw.get("ProviderName") or "").casefold() != PROVIDER
    ):
        return None
    parts = raw.get("StringInserts")
    if not isinstance(parts, list) or len(parts) != 5:
        return None
    try:
        part_number = int(parts[0])
        total_parts = int(parts[1])
    except (ValueError, TypeError):
        return None
    script = parts[2]
    block_id = parts[3]
    if (
        not 1 <= total_parts <= MAX_PARTS
        or not 1 <= part_number <= total_parts
        or not isinstance(script, str)
        or not script
        or not isinstance(block_id, str)
        or not block_id.strip()
    ):
        return None
    event_id = str(event.get("event_id") or "").strip()
    device_id = str(event.get("device_id") or "").strip()
    timestamp = event.get("event_time")
    if (
        not event_id or not device_id
        or not isinstance(timestamp, datetime)
        or timestamp.tzinfo is None
    ):
        return None
    return part_number, total_parts, script, block_id.casefold(), event_id, device_id, timestamp


def is_complete_script_block(events: Sequence[Mapping[str, Any]]) -> bool:
    if not events:
        return False
    fragments = [_fragment(event) for event in events]
    if any(part is None for part in fragments):
        return False
    first = fragments[0]
    total = first[1]
    if len(fragments) != total:
        return False
    if any(
        part[1] != total or part[3] != first[3] or part[5] != first[5]
        for part in fragments
    ):
        return False
    return {part[0] for part in fragments} == set(range(1, total + 1))


def detect_suspicious_script_block(
    events: Sequence[Mapping[str, Any]],
) -> DetectionCandidate | None:
    """Return a candidate only for a validated complete script block.

    Missing/duplicate/mismatched fragments are not acknowledged as complete.
    All contributing event IDs become evidence links if a signature matches.
    """
    if not events:
        return None
    fragments = [_fragment(event) for event in events]
    if any(part is None for part in fragments):
        return None
    first = fragments[0]
    total = first[1]
    if (
        len(fragments) != total
        or any(
            part[1] != total
            or part[3] != first[3]
            or part[5] != first[5]
            for part in fragments
        )
    ):
        return None
    by_number = {part[0]: part for part in fragments}
    if set(by_number) != set(range(1, total + 1)):
        return None

    script = "".join(by_number[i][2] for i in range(1, total + 1))
    if len(script) > MAX_SCRIPT_CHARS:
        return None
    if not DYNAMIC_EXEC.search(script):
        return None
    if not (REMOTE_FETCH.search(script) or BASE64_DECODE.search(script)):
        return None

    ordered = [by_number[i] for i in range(1, total + 1)]
    timestamps = [part[6] for part in ordered]
    return DetectionCandidate(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        severity="high",
        device_id=first[5],
        grouping_basis="device_script_block",
        event_ids=tuple(part[4] for part in ordered),
        event_count=total,
        window_start=min(timestamps),
        window_end=max(timestamps),
    )
