"""WIN-005: Windows user-account disabled (4725) or deleted (4726).

This detector reports observed account lifecycle activity; it never changes
accounts or modifies the collected event evidence.
"""
from datetime import datetime
from typing import Any, Mapping

from app.analysis.detection_candidate import DetectionCandidate

RULE_ID = "RULE-WIN-005"
PROVIDER = "Microsoft-Windows-Security-Auditing"
ACCOUNT_EVENTS = {
    4725: "Windows User Account Disabled",
    4726: "Windows User Account Deleted",
}


def detect_account_disable_or_delete(
    event: Mapping[str, Any],
) -> DetectionCandidate | None:
    """Interpret only Security-Auditing 4725/4726 with a recorded target user.

    Both events encode TargetUserName, TargetDomainName and TargetSid as
    StringInserts[0:3]. The affected user is not the initiating subject.
    """
    raw = event.get("raw_event")
    if not isinstance(raw, dict):
        return None
    try:
        number = int(raw.get("EventID"))
    except (TypeError, ValueError):
        return None
    if (
        number not in ACCOUNT_EVENTS
        or str(raw.get("Channel") or "").strip().casefold() != "security"
        or str(raw.get("ProviderName") or "").strip().casefold()
        != PROVIDER.casefold()
    ):
        return None

    inserts = raw.get("StringInserts")
    if not isinstance(inserts, list) or len(inserts) < 3:
        return None
    target_name = str(inserts[0] or "").strip()
    target_domain = str(inserts[1] or "").strip()
    if not target_name or target_name == "-" or target_name.endswith("$"):
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

    affected_user = (
        f"{target_domain}\\{target_name}"
        if target_domain and target_domain != "-" else target_name
    )
    return DetectionCandidate(
        rule_id=RULE_ID,
        rule_name=ACCOUNT_EVENTS[number],
        severity="medium",
        device_id=device_id,
        target_user=affected_user,
        grouping_basis="device_event",
        event_ids=(stored_id,),
        event_count=1,
        window_start=event_time,
        window_end=event_time,
    )
