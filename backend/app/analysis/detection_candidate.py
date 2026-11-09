"""Shared persistence contract for independent Windows and Linux rules.

This is intentionally compatible with the existing WIN-001 detection fields.
Raw evidence stays in security_events and detection_events links to it.
"""
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol


class DetectionCandidateLike(Protocol):
    rule_id: str
    rule_name: str
    severity: str
    device_id: str | None
    target_user: str | None
    source_ip: str | None
    logon_type: int | None
    grouping_basis: str
    event_ids: tuple[str, ...]
    event_count: int
    window_start: datetime
    window_end: datetime


@dataclass(frozen=True)
class DetectionCandidate:
    rule_id: str
    rule_name: str
    severity: str
    device_id: str | None
    grouping_basis: str
    event_ids: tuple[str, ...]
    event_count: int
    window_start: datetime
    window_end: datetime
    target_user: str | None = None
    source_ip: str | None = None
    logon_type: int | None = None
