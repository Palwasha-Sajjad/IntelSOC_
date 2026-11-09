"""WIN-007: Windows Security account password-change attempt (4723).

The event records an attempt, not proof that a password changed.
Only alert on source-authenticated Windows Security event evidence.
"""
from datetime import datetime
from typing import Any, Mapping

from app.analysis.detection_candidate import DetectionCandidate

RULE_ID = "RULE-WIN-007"
RULE_NAME = "Windows User Password Change Attempt"
PROVIDER = "Microsoft-Windows-Security-Auditing"


def detect_password_change_attempt(
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
        number != 4723
        or str(raw.get("Channel") or "").strip().casefold() != "security"
        or str(raw.get("ProviderName") or "").strip().casefold()
        != PROVIDER.casefold()
    ):
        return None

    # Windows 4723 insertion order: TargetUserName, TargetDomainName,
    # TargetSid, SubjectUserSid, SubjectUserName, SubjectDomainName, ...
    inserts = raw.get("StringInserts")
    if not isinstance(inserts, list) or len(inserts) < 3:
        return None
    name = str(inserts[0] or "").strip()
    domain = str(inserts[1] or "").strip()
    if not name or name == "-" or name.endswith("$"):
        return None

    stored_id = str(event.get("event_id") or "").strip()
    device_id = str(event.get("device_id") or "").strip()
    event_time = event.get("event_time")
    if (
        not stored_id or not device_id
        or not isinstance(event_time, datetime)
        or event_time.tzinfo is None
    ):
        return None

    target = f"{domain}\\{name}" if domain and domain != "-" else name
    return DetectionCandidate(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        severity="medium",
        device_id=device_id,
        target_user=target,
        grouping_basis="device_event",
        event_ids=(stored_id,),
        event_count=1,
        window_start=event_time,
        window_end=event_time,
    )
