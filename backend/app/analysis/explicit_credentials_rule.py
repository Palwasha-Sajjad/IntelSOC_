"""WIN-012: conservative explicit-credential logon detection (Windows 4648).

An Event 4648 alone is not malicious. Only alert on explicit credentials
used from a shell process with distinct actor/target and a valid nonlocal
source IP. Retain all 14 original event fields in unmodified raw evidence.
"""
from datetime import datetime
from ipaddress import ip_address
import ntpath
from typing import Any, Mapping

from app.analysis.detection_candidate import DetectionCandidate

RULE_ID = "RULE-WIN-012"
RULE_NAME = "Unusual Explicit Credential Use"
PROVIDER = "microsoft-windows-security-auditing"
SHELLS = {"powershell.exe", "pwsh.exe", "cmd.exe"}


def detect_unusual_explicit_credentials(
    event: Mapping[str, Any],
) -> DetectionCandidate | None:
    raw = event.get("raw_event")
    if not isinstance(raw, dict):
        return None
    try:
        event_number = int(raw.get("EventID"))
    except (TypeError, ValueError):
        return None
    if (
        event_number != 4648
        or str(raw.get("Channel") or "").strip().casefold() != "security"
        or str(raw.get("ProviderName") or "").strip().casefold() != PROVIDER
    ):
        return None

    # Windows Event 4648 inserts: 0 actor SID, 1 actor user, 2 actor
    # domain, 3 logon ID, 4 GUID, 5 target user, 6 target domain,
    # 7 target GUID, 8 target server, 9 target info, 10 process ID,
    # 11 process name, 12 source IP, 13 source port.
    inserts = raw.get("StringInserts")
    if not isinstance(inserts, list) or len(inserts) != 14:
        return None
    if not all(isinstance(inserts[i], str) for i in (1, 2, 5, 6, 11, 12)):
        return None

    actor = (inserts[2].strip().casefold(), inserts[1].strip().casefold())
    target = (inserts[6].strip().casefold(), inserts[5].strip().casefold())
    if (
        not all(actor) or not all(target)
        or any(value == "-" for value in (*actor, *target))
        or actor == target
    ):
        return None

    process = ntpath.basename(inserts[11].strip().strip('"')).casefold()
    if process not in SHELLS:
        return None

    try:
        address = ip_address(inserts[12].strip())
    except ValueError:
        return None
    if address.is_loopback or address.is_unspecified or address.is_link_local:
        return None

    event_id = str(event.get("event_id") or "").strip()
    device_id = str(event.get("device_id") or "").strip()
    timestamp = event.get("event_time")
    if (
        not event_id or not device_id
        or not isinstance(timestamp, datetime) or timestamp.tzinfo is None
    ):
        return None

    return DetectionCandidate(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        severity="medium",
        device_id=device_id,
        grouping_basis="device_event",
        event_ids=(event_id,),
        event_count=1,
        window_start=timestamp,
        window_end=timestamp,
        target_user=inserts[5].strip(),
        source_ip=str(address),
    )
