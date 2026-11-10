import ipaddress
import re
from datetime import datetime
from typing import Any, Mapping

from app.analysis.detection_candidate import DetectionCandidate
from app.linux_src_ip import extract_linux_source_ip


RULE_ID = "RULE-LIN-005"
RULE_NAME = "Suspicious Sudo Activity"

_STANDARD_SUDO_RE = re.compile(
    r"^(?P<actor>[^:]+?)\s*:\s*"
    r".*?\bUSER=(?P<target>[^\s;]+)\s*;\s*"
    r"COMMAND=(?P<command>.+)$",
    re.IGNORECASE,
)

_NOT_IN_SUDOERS_RE = re.compile(
    r"^(?P<actor>[^:]+?)\s*:\s*.*\bNOT in sudoers\b",
    re.IGNORECASE,
)

_AUTH_FAILURE_RE = re.compile(
    r"(?i)\b(?:authentication failure|auth(?:entication)? failure)\b"
)

_USER_FIELD_RE = re.compile(r"(?i)(?:^|\s)user=(?P<user>[^\s;]+)")


def detect_suspicious_sudo(
    event: Mapping[str, Any],
) -> DetectionCandidate | None:
    """Return LIN-005 only for evidence-backed suspicious sudo activity.

    Ordinary local successful sudo commands are intentionally benign.
    A candidate is produced when either:
    - original evidence carries a validated remote source IP; or
    - the sudo record explicitly reports an authorization/authentication failure.
    """

    event_id = str(event.get("event_id") or "").strip()
    device_id = str(event.get("device_id") or "").strip()
    event_time = event.get("event_time")
    raw_event = event.get("raw_event")
    normalized_ip = str(event.get("src_ip") or "").strip()

    if (
        not event_id
        or not device_id
        or not isinstance(event_time, datetime)
        or event_time.tzinfo is None
        or not isinstance(raw_event, dict)
    ):
        return None

    syslog_identifier = str(
        raw_event.get("SYSLOG_IDENTIFIER") or ""
    ).strip().casefold()
    command_name = str(raw_event.get("_COMM") or "").strip().casefold()

    if syslog_identifier != "sudo" and command_name != "sudo":
        return None

    message = str(
        raw_event.get("MESSAGE")
        or event.get("message")
        or ""
    ).strip()

    if not message:
        return None

    source_ip = _validated_matching_source_ip(
        normalized_ip,
        raw_event,
    )

    authorization_failure = bool(
        _NOT_IN_SUDOERS_RE.search(message)
        or _AUTH_FAILURE_RE.search(message)
    )

    # A normalized source address that is not backed by original evidence
    # must never make a local sudo event look remote.
    if normalized_ip and source_ip is None:
        return None

    if source_ip is None and not authorization_failure:
        return None

    actor = _extract_actor(message)
    target = _extract_target_user(message)

    if source_ip is not None:
        grouping_basis = (
            "device_source_ip_user"
            if actor is not None
            else "device_source_ip"
        )
        severity = "high" if authorization_failure else "medium"
    else:
        grouping_basis = (
            "device_user_sudo_failure"
            if actor is not None
            else "device_sudo_failure"
        )
        severity = "high"

    return DetectionCandidate(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        severity=severity,
        device_id=device_id,
        target_user=actor or target,
        source_ip=source_ip,
        logon_type=None,
        grouping_basis=grouping_basis,
        event_ids=(event_id,),
        event_count=1,
        window_start=event_time,
        window_end=event_time,
    )


def _validated_matching_source_ip(
    normalized_ip: str,
    raw_event: Mapping[str, Any],
) -> str | None:
    if not normalized_ip:
        return None

    try:
        normalized = ipaddress.ip_address(normalized_ip)
    except ValueError:
        return None

    if normalized.is_unspecified:
        return None

    evidence_ip = extract_linux_source_ip(dict(raw_event))
    if evidence_ip is None:
        return None

    try:
        evidence = ipaddress.ip_address(evidence_ip)
    except ValueError:
        return None

    if evidence != normalized:
        return None

    return str(normalized)


def _extract_actor(message: str) -> str | None:
    standard = _STANDARD_SUDO_RE.match(message)
    if standard is not None:
        actor = standard.group("actor").strip()
        return actor or None

    denied = _NOT_IN_SUDOERS_RE.match(message)
    if denied is not None:
        actor = denied.group("actor").strip()
        return actor or None

    users = [
        match.group("user").strip()
        for match in _USER_FIELD_RE.finditer(message)
        if match.group("user").strip()
    ]
    return users[-1] if users else None


def _extract_target_user(message: str) -> str | None:
    standard = _STANDARD_SUDO_RE.match(message)
    if standard is None:
        return None
    target = standard.group("target").strip()
    return target or None
