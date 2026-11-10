import re
from datetime import datetime
from typing import Any, Mapping

from app.analysis.detection_candidate import DetectionCandidate


RULE_ID = "RULE-LIN-004"
RULE_NAME = "Linux Identity or Privilege Change"

_ACCOUNT_TYPES = {
    "ADD_USER": "high",
    "DEL_USER": "high",
    "USER_MGMT": "medium",
    "ADD_GROUP": "high",
    "DEL_GROUP": "high",
    "GRP_MGMT": "medium",
}

_IDENTITY_KEY = "intelsoc_identity_change"

_HEADER_RE = re.compile(
    r"^type=(?P<record_type>[A-Z0-9_]+)\s+"
    r"msg=audit\([^)]*\):\s*(?P<body>.*)$"
)

_FIELD_RE = re.compile(
    r'(?P<name>[A-Za-z0-9_]+)=(?:"(?P<quoted>[^"]*)"|(?P<bare>\S+))'
)

_AUDIT_SUCCESS_RE = re.compile(
    r"(?i)(?:^|[\\s'])res=success(?:$|[\\s'])"
)


def detect_linux_identity_change(
    event: Mapping[str, Any],
) -> DetectionCandidate | None:
    """Detect approved Linux account/group changes and keyed identity-file writes.

    This rule intentionally accepts only already-approved audit telemetry:
    account/group record types and successful SYSCALL records carrying the
    exact intelsoc_identity_change audit key. No generic process execution
    evidence is accepted.
    """

    event_id = str(event.get("event_id") or "").strip()
    device_id = str(event.get("device_id") or "").strip()
    event_time = event.get("event_time")
    raw_event = event.get("raw_event")

    if (
        not event_id
        or not device_id
        or not isinstance(event_time, datetime)
        or event_time.tzinfo is None
        or not isinstance(raw_event, dict)
    ):
        return None

    raw_line = str(
        raw_event.get("log")
        or event.get("message")
        or ""
    ).strip()

    if not raw_line:
        return None

    match = _HEADER_RE.match(raw_line)
    if match is None:
        return None

    record_type = match.group("record_type")
    fields = _parse_fields(match.group("body"))

    if record_type in _ACCOUNT_TYPES:
        body = match.group("body")
        if _AUDIT_SUCCESS_RE.search(body) is None:
            return None

        account = _account_subject(fields)
        grouping_basis = (
            "device_audit_type_account"
            if account is not None
            else "device_audit_type"
        )

        return DetectionCandidate(
            rule_id=RULE_ID,
            rule_name=RULE_NAME,
            severity=_ACCOUNT_TYPES[record_type],
            device_id=device_id,
            target_user=account,
            source_ip=None,
            logon_type=None,
            grouping_basis=grouping_basis,
            event_ids=(event_id,),
            event_count=1,
            window_start=event_time,
            window_end=event_time,
        )

    if record_type != "SYSCALL":
        return None

    if str(fields.get("success") or "").casefold() != "yes":
        return None

    audit_key = str(fields.get("key") or "").strip()
    if audit_key != _IDENTITY_KEY:
        return None

    actor = _actor_from_audit_fields(fields)

    return DetectionCandidate(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        severity="high",
        device_id=device_id,
        target_user=actor,
        source_ip=None,
        logon_type=None,
        grouping_basis=(
            "device_user_identity_file_change"
            if actor is not None
            else "device_identity_file_change"
        ),
        event_ids=(event_id,),
        event_count=1,
        window_start=event_time,
        window_end=event_time,
    )


def _parse_fields(body: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for match in _FIELD_RE.finditer(body):
        fields[match.group("name")] = (
            match.group("quoted")
            if match.group("quoted") is not None
            else match.group("bare")
        )
    return fields


def _clean_identity(value: Any) -> str | None:
    text = str(value or "").strip().strip("'")
    if (
        not text
        or text in {"?", "-", "(unknown)"}
        or text.startswith("unknown(")
    ):
        return None
    return text


def _account_subject(fields: Mapping[str, str]) -> str | None:
    # Synthetic/portable audit records often expose acct=, while Ubuntu's
    # account-management records commonly append the resolved subject as ID=.
    account = _clean_identity(fields.get("acct"))
    if account is not None:
        return account
    return _clean_identity(fields.get("ID"))


def _actor_from_audit_fields(
    fields: Mapping[str, str],
) -> str | None:
    # Audit IDs are retained only as a stable evidence label. We do not try
    # to resolve numeric UIDs to names inside the detection engine.
    auid = _clean_identity(fields.get("auid"))
    if auid is not None and auid != "4294967295":
        return f"auid:{auid}"

    uid = _clean_identity(fields.get("uid"))
    if uid is not None:
        return f"uid:{uid}"

    return None
