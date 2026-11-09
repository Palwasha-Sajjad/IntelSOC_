"""WIN-006: Windows Security account lockout event (4740).

Observed lockouts produce a detection. No account operations are performed.
The original Windows payload remains intact for investigation.
"""
from datetime import datetime
from typing import Any, Mapping

from app.analysis.detection_candidate import DetectionCandidate

RULE_ID = "RULE-WIN-006"
RULE_NAME = "Windows User Account Locked Out"
PROVIDER = "Microsoft-Windows-Security-Auditing"


def detect_account_lockout(
    event: Mapping[str, Any],
) -> DetectionCandidate | None:
    """Extract the affected user, never confuse it with the actor or caller.

    Windows 4740 starts with TargetUserName, TargetDomainName, TargetSid.
    The collector's StringInserts preserve the event's field order.
    """
    raw = event.get("raw_event")
    if not isinstance(raw, dict):
        return None
    try:
        number = int(raw.get("EventID"))
    except (ValueError, TypeError):
        return None
    if (
        number != 4740
        or str(raw.get("Channel") or "").strip().casefold() != "security"
        or str(raw.get("ProviderName") or "").strip().casefold()
        != PROVIDER.casefold()
    ):
        return None

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

    affected_user = f"{domain}\\{name}" if domain and domain != "-" else name
    return DetectionCandidate(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        severity="medium",
        device_id=device_id,
        target_user=affected_user,
        grouping_basis="device_event",
        event_ids=(stored_id,),
        event_count=1,
        window_start=event_time,
        window_end=event_time,
    )
