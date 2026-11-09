"""WIN-004: Windows user-account creation (4720) or enablement (4722).

Only the original Security-Auditing event and its recorded account identity
are evidence. This rule does not modify user accounts or raw event contents.
"""
from datetime import datetime
from typing import Any, Mapping

from app.analysis.detection_candidate import DetectionCandidate

RULE_ID = "RULE-WIN-004"
PROVIDER = "Microsoft-Windows-Security-Auditing"
ACCOUNT_EVENTS = {
    4720: "Windows User Account Created",
    4722: "Windows User Account Enabled",
}


def detect_account_lifecycle(
    event: Mapping[str, Any],
) -> DetectionCandidate | None:
    """Return one detection for a supported user-account lifecycle event.

    Fluent Bit Windows StringInserts follows event XML data order for
    4720/4722: TargetUserName, TargetDomainName, TargetSid,
    SubjectUserSid, SubjectUserName, SubjectDomainName, ...
    """
    raw = event.get("raw_event")
    if not isinstance(raw, dict):
        return None
    try:
        event_id = int(raw.get("EventID"))
    except (TypeError, ValueError):
        return None

    if (
        event_id not in ACCOUNT_EVENTS
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
    target_sid = str(inserts[2] or "").strip()
    if not target_name or target_name == "-" or target_name.endswith("$"):
        # No verified user name, or the target represents a computer account.
        return None

    event_uuid = str(event.get("event_id") or "").strip()
    device_id = str(event.get("device_id") or "").strip()
    event_time = event.get("event_time")
    if (
        not event_uuid or not device_id
        or not isinstance(event_time, datetime)
        or event_time.tzinfo is None
    ):
        return None

    # The target account is the affected identity, not the actor.
    # Prefer the recorded domain-qualified name, without inventing a SID.
    target_user = (
        f"{target_domain}\\{target_name}"
        if target_domain and target_domain != "-" else target_name
    )
    # Preserve the SID exclusively in the unmodified raw event. Never
    # mistake SubjectUserSid (the initiating principal) for TargetSid.
    _ = target_sid

    return DetectionCandidate(
        rule_id=RULE_ID,
        rule_name=ACCOUNT_EVENTS[event_id],
        severity="medium",
        device_id=device_id,
        target_user=target_user,
        grouping_basis="device_event",
        event_ids=(event_uuid,),
        event_count=1,
        window_start=event_time,
        window_end=event_time,
    )
