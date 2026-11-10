from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import ip_address
import re
from typing import Any, Iterable, Mapping

from app.analysis.detection_candidate import DetectionCandidate


RULE_ID = "RULE-LIN-002"
RULE_NAME = "SSH Failures Followed by Successful Login"
THRESHOLD = 5
WINDOW = timedelta(minutes=5)
SEVERITY = "high"

_FAILED_AUTH_RE = re.compile(
    r"^Failed\s+(?P<method>\S+)\s+for\s+"
    r"(?:(?:invalid\s+user)\s+)?"
    r"(?P<user>\S+)\s+from\s+"
    r"(?P<source_ip>\S+)\s+port\s+\d+\b",
    re.IGNORECASE,
)

_ACCEPTED_AUTH_RE = re.compile(
    r"^Accepted\s+(?P<method>\S+)\s+for\s+"
    r"(?P<user>\S+)\s+from\s+"
    r"(?P<source_ip>\S+)\s+port\s+\d+\b",
    re.IGNORECASE,
)

_ALLOWED_METHODS = {
    "password",
    "publickey",
    "keyboard-interactive",
    "keyboard-interactive/pam",
    "none",
}


@dataclass(frozen=True)
class _SshAuthEvent:
    event_id: str
    device_id: str
    event_time: datetime
    target_user: str
    source_ip: str
    is_success: bool


def correlate_ssh_failed_then_success(
    events: Iterable[Mapping[str, Any]],
    *,
    threshold: int = THRESHOLD,
    window: timedelta = WINDOW,
) -> list[DetectionCandidate]:
    """Correlate an SSH failure burst with a later successful authentication."""

    if threshold < 2:
        raise ValueError("threshold must be at least 2")
    if window <= timedelta(0):
        raise ValueError("window must be positive")

    prepared = _qualify_events(events)
    prepared.sort(
        key=lambda item: (
            item.event_time,
            item.is_success,
            item.event_id,
        )
    )

    pending: dict[tuple[str, str, str], deque[_SshAuthEvent]] = defaultdict(deque)
    candidates: list[DetectionCandidate] = []

    for event in prepared:
        key = (
            event.device_id,
            event.source_ip,
            event.target_user,
        )
        queue = pending[key]
        cutoff = event.event_time - window

        while queue and queue[0].event_time < cutoff:
            queue.popleft()

        if not event.is_success:
            queue.append(event)
            continue

        if len(queue) < threshold:
            continue

        evidence = list(queue)[-threshold:]

        if evidence[-1].event_time >= event.event_time:
            continue

        event_ids = tuple(item.event_id for item in evidence) + (
            event.event_id,
        )

        candidates.append(
            DetectionCandidate(
                rule_id=RULE_ID,
                rule_name=RULE_NAME,
                severity=SEVERITY,
                device_id=event.device_id,
                target_user=event.target_user,
                source_ip=event.source_ip,
                logon_type=None,
                grouping_basis="device_source_ip_user",
                event_ids=event_ids,
                event_count=len(event_ids),
                window_start=evidence[0].event_time,
                window_end=event.event_time,
            )
        )

        # A later success requires a fresh failure burst.
        queue.clear()

    return candidates


def _qualify_events(
    events: Iterable[Mapping[str, Any]],
) -> list[_SshAuthEvent]:
    qualified: list[_SshAuthEvent] = []
    seen_event_ids: set[str] = set()

    for event in events:
        event_id = str(event.get("event_id") or "").strip()
        device_id = str(event.get("device_id") or "").strip()
        event_time = event.get("event_time")
        raw_event = event.get("raw_event")
        normalized_ip = str(event.get("src_ip") or "").strip()

        if (
            not event_id
            or not device_id
            or event_id in seen_event_ids
            or not isinstance(event_time, datetime)
            or event_time.tzinfo is None
            or not isinstance(raw_event, dict)
            or raw_event.get("_SYSTEMD_UNIT") != "ssh.service"
            or not normalized_ip
        ):
            continue

        try:
            parsed_normalized_ip = ip_address(normalized_ip)
        except ValueError:
            continue

        if parsed_normalized_ip.is_unspecified:
            continue

        canonical_ip = str(parsed_normalized_ip)
        message = str(
            raw_event.get("MESSAGE")
            or event.get("message")
            or ""
        ).strip()

        match = _FAILED_AUTH_RE.match(message)
        is_success = False

        if match is None:
            match = _ACCEPTED_AUTH_RE.match(message)
            is_success = match is not None

        if match is None:
            continue

        method = match.group("method").casefold()
        if method not in _ALLOWED_METHODS:
            continue

        try:
            parsed_evidence_ip = ip_address(match.group("source_ip"))
        except ValueError:
            continue

        if parsed_evidence_ip.is_unspecified:
            continue

        evidence_ip = str(parsed_evidence_ip)
        if evidence_ip != canonical_ip:
            continue

        target_user = match.group("user").strip()
        if not target_user:
            continue

        seen_event_ids.add(event_id)
        qualified.append(
            _SshAuthEvent(
                event_id=event_id,
                device_id=device_id,
                event_time=event_time,
                target_user=target_user,
                source_ip=canonical_ip,
                is_success=is_success,
            )
        )

    return qualified
