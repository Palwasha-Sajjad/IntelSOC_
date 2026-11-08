import re
from datetime import datetime, timezone
from uuid import NAMESPACE_URL, uuid5


SUPPORTED_ACCOUNT_TYPES = {
    "ADD_USER",
    "DEL_USER",
    "USER_MGMT",
    "ADD_GROUP",
    "DEL_GROUP",
    "GRP_MGMT",
}


AUDIT_HEADER_RE = re.compile(
    r"^type=(?P<record_type>[A-Z0-9_]+)\s+"
    r"msg=audit\("
    r"(?P<seconds>\d+)"
    r"(?:\.(?P<fraction>\d+))?"
    r":(?P<serial>\d+)"
    r"\):\s*"
    r"(?P<body>.*)$"
)


def normalize_linux_audit_event(
    record: dict,
    hostname: str,
) -> dict:
    """
    Normalize one supported Linux audit account/group record.

    Expected record format:
    {
        "log": "type=USER_MGMT msg=audit(...): ..."
    }

    Hostname comes from IntelSOC's authenticated device record,
    not from the untrusted audit payload.
    """

    if not isinstance(record, dict):
        raise ValueError(
            "Linux audit event must be a JSON object"
        )

    raw_line = str(
        record.get("log") or ""
    ).strip()

    if not raw_line:
        raise ValueError(
            "Linux audit event is missing log data"
        )

    hostname = str(hostname).strip()

    if not hostname:
        raise ValueError(
            "Linux audit event requires hostname"
        )

    match = AUDIT_HEADER_RE.match(raw_line)

    if not match:
        raise ValueError(
            "Invalid Linux audit record format"
        )

    record_type = match.group("record_type")

    if record_type not in SUPPORTED_ACCOUNT_TYPES:
        raise ValueError(
            f"Unsupported Linux audit record type: "
            f"{record_type}"
        )

    seconds = int(match.group("seconds"))

    fraction = match.group("fraction") or "0"

    microseconds = int(
        (fraction + "000000")[:6]
    )

    timestamp = datetime.fromtimestamp(
        seconds,
        tz=timezone.utc,
    ).replace(
        microsecond=microseconds
    )

    serial = match.group("serial")

    identity = (
        f"linux-audit:{hostname.lower()}:"
        f"{seconds}:{fraction}:{serial}:"
        f"{record_type}"
    )

    return {
        "schema_version": "1.0",
        "event_id": str(
            uuid5(NAMESPACE_URL, identity)
        ),
        "timestamp": timestamp.isoformat(),
        "source": "linux_audit",
        "hostname": hostname,
        "event_type": "linux_account_audit_event",
        "src_ip": None,
        "message": raw_line[:65536],
        "raw_event": dict(record),
    }
