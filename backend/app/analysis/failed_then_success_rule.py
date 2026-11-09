"""R2-D1: correlate a burst of Windows 4625 failures with a later 4624 success.

Pure analysis only: existing events and evidence remain unchanged. A missing
network address is never used to match remote authentication attempts.
"""
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any, Iterable, Mapping

from app.analysis.detection_candidate import DetectionCandidate
from app.analysis.windows_event_extractor import extract_windows_failed_logon

RULE_ID = "RULE-WIN-008"
RULE_NAME = "Failed Logins Followed by Successful Login"
WINDOW = timedelta(minutes=5)
THRESHOLD = 5
PROVIDER = "microsoft-windows-security-auditing"
LOCAL_LOGON_TYPES = {2, 11}
REMOTE_LOGON_TYPES = {3, 10}


def _identity(name: Any, domain: Any) -> str | None:
    user = str(name or "").strip()
    scope = str(domain or "").strip()
    if not user or user == "-" or user.endswith("$") or not scope or scope == "-":
        return None
    if user.casefold() in {"system", "local service", "network service"}:
        return None
    return f"{scope}\\{user}"


def _event_id(raw: dict[str, Any]) -> int | None:
    try:
        return int(raw.get("EventID"))
    except (ValueError, TypeError):
        return None


def _valid_record(event: Mapping[str, Any], number: int) -> bool:
    raw = event.get("raw_event")
    dt = event.get("event_time")
    return (
        bool(str(event.get("event_id") or "").strip())
        and bool(str(event.get("device_id") or "").strip())
        and isinstance(dt, datetime)
        and dt.tzinfo is not None
        and isinstance(raw, dict)
        and _event_id(raw) == number
        and str(raw.get("Channel") or "").strip().casefold() == "security"
        and str(raw.get("ProviderName") or "").strip().casefold() == PROVIDER
    )


def _ip(value: Any) -> str | None:
    import ipaddress

    value = str(value or "").strip()
    if value in {"", "-"}:
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if address.is_loopback or address.is_unspecified:
        return None
    return str(address)


def _success(event: Mapping[str, Any]) -> tuple[str, int, str | None] | None:
    if not _valid_record(event, 4624):
        return None
    inserts = event["raw_event"].get("StringInserts")
    if not isinstance(inserts, list) or len(inserts) < 20:
        return None
    identity = _identity(inserts[5], inserts[6])
    try:
        logon_type = int(inserts[8])
    except (ValueError, TypeError):
        return None
    if identity is None or logon_type not in (LOCAL_LOGON_TYPES | REMOTE_LOGON_TYPES):
        return None
    address = _ip(inserts[18])
    if logon_type in REMOTE_LOGON_TYPES and address is None:
        return None
    return identity, logon_type, address if logon_type in REMOTE_LOGON_TYPES else None


def _failure(event: Mapping[str, Any]) -> tuple[str, int, str | None] | None:
    if not _valid_record(event, 4625):
        return None
    evidence = extract_windows_failed_logon(event["raw_event"])
    if evidence is None:
        return None
    identity = _identity(evidence.target_user, evidence.target_domain)
    logon_type = evidence.logon_type
    if identity is None or logon_type not in (LOCAL_LOGON_TYPES | REMOTE_LOGON_TYPES):
        return None
    address = _ip(evidence.source_ip)
    if logon_type in REMOTE_LOGON_TYPES and address is None:
        return None
    return identity, logon_type, address if logon_type in REMOTE_LOGON_TYPES else None


def correlate_failed_then_successful_logins(
    events: Iterable[Mapping[str, Any]],
    *,
    threshold: int = THRESHOLD,
    window: timedelta = WINDOW,
) -> list[DetectionCandidate]:
    """Use one successful sign-in as trigger; never reuse its prior failures.

    Groups are device + domain-qualified account + logon type + (for remote
    logons) exact source IP. Five distinct preceding failures are required.
    """
    if threshold < 2 or window <= timedelta(0):
        raise ValueError("threshold and window must be positive")

    prepared = []
    seen = set()
    for event in events:
        stored_id = str(event.get("event_id") or "").strip()
        if not stored_id or stored_id in seen:
            continue
        failed = _failure(event)
        succeeded = None if failed else _success(event)
        if failed is None and succeeded is None:
            continue
        seen.add(stored_id)
        identity, logon_type, ip = failed or succeeded
        key = (str(event["device_id"]), identity.casefold(), logon_type, ip)
        prepared.append((
            event["event_time"], stored_id, key, identity, ip,
            logon_type, failed is None,
        ))

    prepared.sort(key=lambda item: (item[0], item[6], item[1]))
    pending = defaultdict(deque)
    candidates = []

    for dt, stored_id, key, identity, ip, logon_type, is_success in prepared:
        queue = pending[key]
        cutoff = dt - window
        while queue and queue[0][0] < cutoff:
            queue.popleft()

        if not is_success:
            queue.append((dt, stored_id))
            continue
        if len(queue) < threshold:
            continue

        # Earliest complete burst in the window, plus the success record.
        evidence = list(queue)[-threshold:]
        first_time = evidence[0][0]
        event_ids = tuple(item[1] for item in evidence) + (stored_id,)
        candidates.append(DetectionCandidate(
            rule_id=RULE_ID,
            rule_name=RULE_NAME,
            severity="high",
            device_id=key[0],
            target_user=identity,
            source_ip=ip,
            logon_type=logon_type,
            grouping_basis=(
                "device_user_logon_type_source_ip"
                if ip else "device_user_local_logon_type"
            ),
            event_ids=event_ids,
            event_count=len(event_ids),
            window_start=first_time,
            window_end=dt,
        ))
        queue.clear()  # Further successes require a fresh failure burst.

    return candidates
