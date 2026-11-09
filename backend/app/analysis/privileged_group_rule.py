"""WIN-003: member added to the built-in local Administrators group."""
from datetime import datetime
from typing import Any, Mapping

from app.analysis.detection_candidate import DetectionCandidate

RULE_ID = "RULE-WIN-003"
RULE_NAME = "Member Added to Local Administrators"
PROVIDER = "Microsoft-Windows-Security-Auditing"
ADMINISTRATORS_SID = "S-1-5-32-544"


def detect_privileged_group_member_added(
    event: Mapping[str, Any],
) -> DetectionCandidate | None:
    """Match genuine-shaped Security 4732, using the group SID, not its name.

    Windows local group names can be localized or renamed. Unrecognized
    group SIDs are not assumed privileged. Raw evidence is never modified.
    """
    raw = event.get("raw_event")
    if not isinstance(raw, dict):
        return None
    try:
        event_id = int(raw.get("EventID"))
    except (TypeError, ValueError):
        return None
    if (
        event_id != 4732
        or str(raw.get("Channel") or "").strip().casefold() != "security"
        or str(raw.get("ProviderName") or "").strip().casefold()
        != PROVIDER.casefold()
    ):
        return None

    # Windows 4732's insertion-string order:
    # MemberName, MemberSid, TargetUserName, TargetDomainName,
    # TargetSid, SubjectUserSid, SubjectUserName, ...
    inserts = raw.get("StringInserts")
    if not isinstance(inserts, list) or len(inserts) < 5:
        return None
    group_sid = str(inserts[4] or "").strip().upper()
    if group_sid != ADMINISTRATORS_SID:
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

    # MemberSid is the affected principal, not the initiating account.
    # Prefer the SID to avoid fabricated or ambiguous user identity.
    member_sid = str(inserts[1] or "").strip()
    member_name = str(inserts[0] or "").strip()
    subject = (
        member_sid if member_sid and member_sid != "-"
        else member_name if member_name and member_name != "-"
        else None
    )

    return DetectionCandidate(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        severity="high",
        device_id=device_id,
        target_user=subject,
        source_ip=None,
        logon_type=None,
        grouping_basis="device_event",
        event_ids=(stored_id,),
        event_count=1,
        window_start=event_time,
        window_end=event_time,
    )
