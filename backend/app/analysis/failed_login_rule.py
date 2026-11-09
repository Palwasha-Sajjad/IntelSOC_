from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Iterable, Mapping

from app.analysis.windows_event_extractor import (
    extract_windows_failed_logon,
)


RULE_ID = "RULE-WIN-001"
RULE_NAME = "Repeated Failed Logins"
DEFAULT_THRESHOLD = 5
DEFAULT_WINDOW = timedelta(minutes=5)
DEFAULT_SEVERITY = "medium"


@dataclass(frozen=True)
class FailedLoginDetectionCandidate:
    """In-memory result produced when the failed-login rule matches."""

    rule_id: str
    rule_name: str
    severity: str
    device_id: str
    target_user: str
    source_ip: str | None
    logon_type: int | None
    grouping_basis: str
    event_ids: tuple[str, ...]
    event_count: int
    window_start: datetime
    window_end: datetime


@dataclass(frozen=True)
class _QualifiedFailure:
    event_id: str
    device_id: str
    event_time: datetime
    target_user: str
    source_ip: str | None
    logon_type: int | None
    grouping_basis: str


def evaluate_repeated_failed_logins(
    events: Iterable[Mapping[str, Any]],
    *,
    threshold: int = DEFAULT_THRESHOLD,
    window: timedelta = DEFAULT_WINDOW,
) -> list[FailedLoginDetectionCandidate]:
    """
    Evaluate stored Windows events for repeated failed-logon activity.

    This function is intentionally side-effect free. It does not write
    alerts, incidents, or analysis state. Replay safety at this stage
    comes from counting each event_id only once.
    """

    if threshold < 2:
        raise ValueError("threshold must be at least 2")

    if window <= timedelta(0):
        raise ValueError("window must be positive")

    qualified = _qualify_events(events)
    grouped: dict[tuple[Any, ...], list[_QualifiedFailure]] = defaultdict(list)

    for failure in qualified:
        grouped[_group_key(failure)].append(failure)

    candidates: list[FailedLoginDetectionCandidate] = []

    for group_events in grouped.values():
        group_events.sort(
            key=lambda item: (
                item.event_time,
                item.event_id,
            )
        )

        active: deque[_QualifiedFailure] = deque()
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
                    FailedLoginDetectionCandidate(
                        rule_id=RULE_ID,
                        rule_name=RULE_NAME,
                        severity=DEFAULT_SEVERITY,
                        device_id=failure.device_id,
                        target_user=failure.target_user,
                        source_ip=failure.source_ip,
                        logon_type=failure.logon_type,
                        grouping_basis=failure.grouping_basis,
                        event_ids=tuple(
                            item.event_id for item in evidence
                        ),
                        event_count=len(evidence),
                        window_start=evidence[0].event_time,
                        window_end=evidence[-1].event_time,
                    )
                )

                episode_triggered = True

    return candidates


def _qualify_events(
    events: Iterable[Mapping[str, Any]],
) -> list[_QualifiedFailure]:
    failures: list[_QualifiedFailure] = []
    seen_event_ids: set[str] = set()

    for event in events:
        event_id = str(event.get("event_id") or "").strip()
        device_id = str(event.get("device_id") or "").strip()
        event_time = event.get("event_time")
        raw_event = event.get("raw_event")

        if (
            not event_id
            or not device_id
            or event_id in seen_event_ids
            or not isinstance(event_time, datetime)
            or event_time.tzinfo is None
            or not isinstance(raw_event, dict)
        ):
            continue

        evidence = extract_windows_failed_logon(raw_event)

        if evidence is None:
            continue

        target_user = str(evidence.target_user or "").strip()

        if not target_user:
            continue

        if evidence.source_ip is not None:
            grouping_basis = "device_user_source_ip"
        else:
            grouping_basis = "device_user_logon_type"

        seen_event_ids.add(event_id)

        failures.append(
            _QualifiedFailure(
                event_id=event_id,
                device_id=device_id,
                event_time=event_time,
                target_user=target_user,
                source_ip=evidence.source_ip,
                logon_type=evidence.logon_type,
                grouping_basis=grouping_basis,
            )
        )

    return failures


def _group_key(
    failure: _QualifiedFailure,
) -> tuple[Any, ...]:
    user_key = failure.target_user.casefold()

    if failure.source_ip is not None:
        return (
            "remote",
            failure.device_id,
            user_key,
            failure.source_ip,
        )

    return (
        "local",
        failure.device_id,
        user_key,
        failure.logon_type,
    )
