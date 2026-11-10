import re
from datetime import datetime
from typing import Any, Mapping

from app.analysis.detection_candidate import DetectionCandidate


RULE_ID = "RULE-LIN-004"
RULE_NAME = "Privileged Group Change"

# High-confidence administrative or privilege-bearing groups. Ordinary groups
# are deliberately excluded to control false positives.
PRIVILEGED_GROUPS = frozenset({
    "root",
    "sudo",
    "wheel",
    "adm",
    "shadow",
    "docker",
    "lxd",
})

_GROUP_TYPES = {
    "ADD_GROUP",
    "DEL_GROUP",
    "GRP_MGMT",
    "USER_MGMT",
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


def detect_linux_privileged_group_change(
    event: Mapping[str, Any],
) -> DetectionCandidate | None:
    """Detect only successful changes involving an explicitly privileged group."""

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
    if record_type not in _GROUP_TYPES:
        return None

    body = match.group("body")
    if _AUDIT_SUCCESS_RE.search(body) is None:
        return None

    fields = _parse_fields(body)
    group = _extract_group(record_type, fields)

    if group is None or group.casefold() not in PRIVILEGED_GROUPS:
        return None

    target = _account_subject(fields)

    # For group-create/delete records the subject itself is normally the group.
    # For USER_MGMT, acct/ID can identify the affected user while grp/group
    # identifies the privileged group. Raw audit evidence retains both.
    if record_type in {"ADD_GROUP", "DEL_GROUP", "GRP_MGMT"}:
        target = target or group

    return DetectionCandidate(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        severity="high",
        device_id=device_id,
        target_user=target,
        source_ip=None,
        logon_type=None,
        grouping_basis=f"device_privileged_group:{group.casefold()}",
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


def _extract_group(
    record_type: str,
    fields: Mapping[str, str],
) -> str | None:
    for name, value in fields.items():
        if name.casefold() in _GROUP_FIELD_NAMES:
            group = _clean_identity(value)
            if group is not None:
                return group

    # Native records can place the affected user in acct= while exposing the
    # changed group through ID=. Prefer an ID only when it is explicitly one
    # of our privileged groups, then fall back to acct= for group records.
    candidate_id = _clean_identity(fields.get("ID"))
    if (
        candidate_id is not None
        and candidate_id.casefold() in PRIVILEGED_GROUPS
    ):
        return candidate_id

    if record_type in {"ADD_GROUP", "DEL_GROUP", "GRP_MGMT"}:
        return _clean_identity(fields.get("acct"))

    return None
