from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import ip_address
import re
from typing import Any, Iterable, Mapping

from app.analysis.detection_candidate import DetectionCandidate


RULE_ID = "RULE-LIN-001"
RULE_NAME = "SSH Brute-Force Attempts"
DEFAULT_THRESHOLD = 5
DEFAULT_WINDOW = timedelta(minutes=5)
DEFAULT_SEVERITY = "medium"

_FAILED_AUTH_RE = re.compile(
    r"^Failed\s+(?P<method>\S+)\s+for\s+"
    r"(?:(?:invalid\s+user)\s+)?"
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
class _QualifiedSshFailure:
    event_id: str
    device_id: str
    event_time: datetime
    target_user: str | None
    source_ip: str
    grouping_basis: str


def evaluate_ssh_bruteforce(
    events: Iterable[Mapping[str, Any]],
    *,
    threshold: int = DEFAULT_THRESHOLD,
    window: timedelta = DEFAULT_WINDOW,
) -> list[DetectionCandidate]:
    """Return deterministic LIN-001 candidates from explicit SSH failures."""

    if threshold < 2:
        raise ValueError("threshold must be at least 2")
    if window <= timedelta(0):
        raise ValueError("window must be positive")

    qualified = _qualify_events(events)
    grouped: dict[tuple[str, ...], list[_QualifiedSshFailure]] = defaultdict(list)

    for failure in qualified:
        grouped[_group_key(failure)].append(failure)

    candidates: list[DetectionCandidate] = []

    for group_events in grouped.values():
        group_events.sort(key=lambda item: (item.event_time, item.event_id))

        active: deque[_QualifiedSshFailure] = deque()
        episode_triggered = False

        for failure in group_events:
            cutoff = failure.event_time - window

            while active and active[0].event_time < cutoff:
                active.popleft()

            if len(active) < threshold - 1:
                episode_triggered = False

            active.append(failure)

            if len(active) >= threshold and not episode_triggered:
                evidence = tuple(active)[-threshold:]

                candidates.append(
                    DetectionCandidate(
                        rule_id=RULE_ID,
                        rule_name=RULE_NAME,
                        severity=DEFAULT_SEVERITY,
                        device_id=failure.device_id,
                        target_user=failure.target_user,
                        source_ip=failure.source_ip,
                        logon_type=None,
                        grouping_basis=failure.grouping_basis,
                        event_ids=tuple(item.event_id for item in evidence),
                        event_count=len(evidence),
                        window_start=evidence[0].event_time,
                        window_end=evidence[-1].event_time,
                    )
                )

                episode_triggered = True

    return candidates


def _qualify_events(
    events: Iterable[Mapping[str, Any]],
) -> list[_QualifiedSshFailure]:
    failures: list[_QualifiedSshFailure] = []
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

        message = str(raw_event.get("MESSAGE") or event.get("message") or "").strip()
        match = _FAILED_AUTH_RE.match(message)

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

        target_user = match.group("user").strip() or None
        grouping_basis = (
            "device_source_ip_user"
            if target_user is not None
            else "device_source_ip"
        )

        seen_event_ids.add(event_id)
        failures.append(
            _QualifiedSshFailure(
                event_id=event_id,
                device_id=device_id,
                event_time=event_time,
                target_user=target_user,
                source_ip=canonical_ip,
                grouping_basis=grouping_basis,
            )
        )

    return failures


def _group_key(
    failure: _QualifiedSshFailure,
) -> tuple[str, ...]:
    if failure.target_user is not None:
        return (
            failure.device_id,
            failure.source_ip,
            failure.target_user,
        )

    return (
        failure.device_id,
        failure.source_ip,
    )
