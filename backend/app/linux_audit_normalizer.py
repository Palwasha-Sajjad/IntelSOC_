import re
from datetime import datetime, timezone
from uuid import NAMESPACE_URL, uuid5


ACCOUNT_AUDIT_TYPES = {
    "ADD_USER",
    "DEL_USER",
    "USER_MGMT",
    "ADD_GROUP",
    "DEL_GROUP",
    "GRP_MGMT",
}


PROCESS_AUDIT_TYPES = {
    "SYSCALL",
    "EXECVE",
    "PROCTITLE",
    "CWD",
    "PATH",
}


SUPPORTED_AUDIT_TYPES = (
    ACCOUNT_AUDIT_TYPES
    | PROCESS_AUDIT_TYPES
)


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
    Normalize one supported Linux audit record.

    Account/group records and selected process-execution
    records are preserved individually. Related process
    records can later be correlated using their shared
    audit timestamp/serial.
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

    if record_type not in SUPPORTED_AUDIT_TYPES:
        raise ValueError(
            f"Unsupported Linux audit record type: "
            f"{record_type}"
        )

    seconds = int(
        match.group("seconds")
    )

    fraction = (
        match.group("fraction")
        or "0"
    )

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

    if record_type in ACCOUNT_AUDIT_TYPES:
        event_type = (
            "linux_account_audit_event"
        )
    else:
        event_type = (
            "linux_process_audit_event"
        )

    # Include the complete raw line so multiple PATH
    # records from the same audit event cannot collide.
    identity = (
        f"linux-audit:"
        f"{hostname.lower()}:"
        f"{seconds}:"
        f"{fraction}:"
        f"{serial}:"
        f"{record_type}:"
        f"{raw_line}"
    )

    return {
        "schema_version": "1.0",
        "event_id": str(
            uuid5(
                NAMESPACE_URL,
                identity,
            )
        ),
        "timestamp": timestamp.isoformat(),
        "source": "linux_audit",
        "hostname": hostname,
        "event_type": event_type,
        "src_ip": None,
        "message": raw_line[:65536],
        "raw_event": dict(record),
    }
