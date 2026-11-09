"""Windows Security log clearing: one high-confidence detection per Event 1102."""
from datetime import datetime
from typing import Any, Mapping

from app.analysis.detection_candidate import DetectionCandidate

RULE_ID = "RULE-WIN-002"
RULE_NAME = "Windows Security Audit Log Cleared"
PROVIDER = "Microsoft-Windows-Eventlog"
SEVERITY = "high"


def detect_security_log_cleared(
    event: Mapping[str, Any],
) -> DetectionCandidate | None:
    """Match only an authentic-shaped Windows Security / Eventlog / 1102."""
    raw = event.get("raw_event")
    if not isinstance(raw, dict):
        return None
    try:
        event_id = int(raw.get("EventID"))
    except (ValueError, TypeError):
        return None
    if (
        event_id != 1102
        or str(raw.get("Channel") or "").strip().casefold() != "security"
        or str(raw.get("ProviderName") or "").strip().casefold()
        != PROVIDER.casefold()
    ):
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

    # The cleared-log actor may be absent in the collector's raw format.
    # Do not infer an identity from the machine hostname or log message.
    inserts = raw.get("StringInserts")
    actor = None
    if isinstance(inserts, list) and len(inserts) >= 2:
        value = str(inserts[1] or "").strip()
        if value and value != "-":
            actor = value

    return DetectionCandidate(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        severity=SEVERITY,
        device_id=device_id,
        target_user=actor,
        grouping_basis="device_event",
        event_ids=(stored_id,),
        event_count=1,
        window_start=event_time,
        window_end=event_time,
    )
