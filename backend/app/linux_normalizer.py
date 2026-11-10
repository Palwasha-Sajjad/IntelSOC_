from datetime import datetime, timezone
from uuid import NAMESPACE_URL, uuid5

from app.linux_src_ip import extract_linux_source_ip


def _classify_linux_record(record: dict) -> str:
    """Return the supported IntelSOC Linux event type."""

    if record.get("_SYSTEMD_UNIT") == "ssh.service":
        return "linux_ssh_event"

    syslog_identifier = str(
        record.get("SYSLOG_IDENTIFIER") or ""
    ).strip().lower()

    command = str(
        record.get("_COMM") or ""
    ).strip().lower()

    if syslog_identifier == "sudo" or command == "sudo":
        return "linux_sudo_event"

    raise ValueError(
        "Unsupported Linux journal event source"
    )


def normalize_linux_event(record: dict) -> dict:
    """
    Convert a supported Linux journal record to IntelSOC's event schema.

    Supported sources:
    - ssh.service
    - sudo journal records
    """

    if not isinstance(record, dict):
        raise ValueError("Linux event must be a JSON object")

    required = (
        "_HOSTNAME",
        "_BOOT_ID",
        "_SOURCE_REALTIME_TIMESTAMP",
        "MESSAGE",
    )

    for field in required:
        if field not in record:
            raise ValueError(
                f"Missing Linux event field: {field}"
            )

    event_type = _classify_linux_record(record)

    hostname = str(record["_HOSTNAME"]).strip()
    boot_id = str(record["_BOOT_ID"]).strip()
    message = str(record["MESSAGE"]).strip()

    if not hostname or not boot_id or not message:
        raise ValueError(
            "Linux event contains empty required fields"
        )

    try:
        microseconds = int(
            record["_SOURCE_REALTIME_TIMESTAMP"]
        )

        if microseconds <= 0:
            raise ValueError(
                "Timestamp must be positive"
            )

        timestamp = datetime.fromtimestamp(
            microseconds / 1_000_000,
            tz=timezone.utc,
        )

    except (
        ValueError,
        TypeError,
        OverflowError,
        OSError,
    ) as error:
        raise ValueError(
            "Invalid Linux journal timestamp"
        ) from error

    identity = (
        f"linux-journald:{hostname}:{boot_id}:"
        f"{microseconds}:"
        f"{record.get('_PID', '')}:"
        f"{message}"
    )

    return {
        "schema_version": "1.0",
        "event_id": str(
            uuid5(NAMESPACE_URL, identity)
        ),
        "timestamp": timestamp.isoformat(),
        "source": "linux_journald",
        "hostname": hostname,
        "event_type": event_type,
        "src_ip": extract_linux_source_ip(record),
        "message": message[:2048],
        "raw_event": dict(record),
    }
