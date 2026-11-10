import re
from datetime import datetime
from typing import Any, Mapping

from app.analysis.detection_candidate import DetectionCandidate


RULE_ID = "RULE-LIN-003"
RULE_NAME = "Sensitive Account Lifecycle Change"

_ACCOUNT_TYPES = {
    "ADD_USER": "high",
    "DEL_USER": "high",
    "USER_MGMT": "medium",
}

_HEADER_RE = re.compile(
    r"^type=(?P<record_type>[A-Z0-9_]+)\s+"
    r"msg=audit\([^)]*\):\s*(?P<body>.*)$"
)

_FIELD_RE = re.compile(
    r'(?P<name>[A-Za-z0-9_]+)=(?:"(?P<quoted>[^"]*)"|(?P<bare>\S+))'
)

_AUDIT_SUCCESS_RE = re.compile(
    r"(?i)(?:^|[\s'])res=success(?:$|[\s'])"
)

_GROUP_FIELD_NAMES = {
    "grp",
    "group",
    "groupname",
    "new_group",
}


def detect_linux_account_lifecycle(
    event: Mapping[str, Any],
) -> DetectionCandidate | None:
    """Detect successful, security-relevant Linux account lifecycle changes.

    LIN-003 owns account creation, deletion and non-group USER_MGMT events.
    Group-management evidence is intentionally left to LIN-004 so the two
    frozen rule contracts remain separate.
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
    if record_type not in _ACCOUNT_TYPES:
        return None

    body = match.group("body")
    if _AUDIT_SUCCESS_RE.search(body) is None:
        return None

    fields = _parse_fields(body)

    # USER_MGMT can represent a group-membership operation. Those records
    # belong to LIN-004 and must not create a second account-lifecycle alert.
    if record_type == "USER_MGMT" and (
        _explicit_group(fields) is not None
        or _looks_like_group_operation(body)
    ):
        return None

    account = _account_subject(fields)

    return DetectionCandidate(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        severity=_ACCOUNT_TYPES[record_type],
        device_id=device_id,
        target_user=account,
        source_ip=None,
        logon_type=None,
        grouping_basis=(
            "device_account"
            if account is not None
            else "device_account_change"
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
    account = _clean_identity(fields.get("acct"))
    if account is not None:
        return account
    return _clean_identity(fields.get("ID"))


def _explicit_group(fields: Mapping[str, str]) -> str | None:
    for name, value in fields.items():
        if name.casefold() in _GROUP_FIELD_NAMES:
            group = _clean_identity(value)
            if group is not None:
                return group
    return None


def _looks_like_group_operation(body: str) -> bool:
    lowered = body.casefold()
    return any(
        marker in lowered
        for marker in (
            "op=add-shadow-group",
            "op=remove-shadow-group",
            "op=adding user to group",
            "op=deleting user from group",
            "op=deleting user from shadow group",
            "op=add-group",
            "op=del-group",
        )
    )
