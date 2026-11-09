"""WIN-010: high-confidence suspicious Windows process creation (4688).

Inspect original Security-Auditing event evidence only. Windows 4688's
NewProcessName (index 5) identifies the executable; CommandLine (index 8)
may be empty when command-line auditing is disabled. Missing evidence
must never be treated as a suspicious process.
"""
from datetime import datetime
import ntpath
import re
from typing import Any, Mapping

from app.analysis.detection_candidate import DetectionCandidate

RULE_ID = "RULE-WIN-010"
RULE_NAME = "Suspicious Windows Process Creation"
PROVIDER = "microsoft-windows-security-auditing"
MAX_COMMAND_LENGTH = 65536

ENCODED_PS = re.compile(r"(?i)(?:^|\s)[-/](?:encodedcommand|enc)(?::|\s|$)")
URL = re.compile(r"(?i)https?://[^\s\"']+")


def detect_suspicious_process_creation(
    event: Mapping[str, Any],
) -> DetectionCandidate | None:
    raw = event.get("raw_event")
    if not isinstance(raw, dict):
        return None
    try:
        number = int(raw.get("EventID"))
    except (ValueError, TypeError):
        return None
    if (
        number != 4688
        or str(raw.get("Channel") or "").strip().casefold() != "security"
        or str(raw.get("ProviderName") or "").strip().casefold() != PROVIDER
    ):
        return None

    inserts = raw.get("StringInserts")
    if not isinstance(inserts, list) or len(inserts) < 9:
        return None

    process_path = inserts[5]
    command_line = inserts[8]
    if not isinstance(process_path, str) or not isinstance(command_line, str):
        return None
    process_path = process_path.strip().strip('"')
    command_line = command_line.strip()
    if not process_path or process_path == "-" or not command_line or command_line == "-":
        return None
    if len(command_line) > MAX_COMMAND_LENGTH:
        return None

    executable = ntpath.basename(process_path).casefold()
    suspicious = (
        executable in {"powershell.exe", "pwsh.exe"}
        and ENCODED_PS.search(command_line) is not None
    ) or (
        executable == "mshta.exe"
        and URL.search(command_line) is not None
    )
    if not suspicious:
        return None

    stored_id = str(event.get("event_id") or "").strip()
    device_id = str(event.get("device_id") or "").strip()
    timestamp = event.get("event_time")
    if (
        not stored_id or not device_id
        or not isinstance(timestamp, datetime)
        or timestamp.tzinfo is None
    ):
        return None

    # Actor and process command remain in immutable raw event evidence.
    return DetectionCandidate(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        severity="high",
        device_id=device_id,
        grouping_basis="device_event",
        event_ids=(stored_id,),
        event_count=1,
        window_start=timestamp,
        window_end=timestamp,
    )
