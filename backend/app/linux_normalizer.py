from datetime import datetime, timezone
from uuid import NAMESPACE_URL, uuid5


def normalize_linux_event(record: dict) -> dict:
    """Convert a Linux SSH journal record to IntelSOC's event schema."""

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
            raise ValueError(f"Missing Linux event field: {field}")

    if record.get("_SYSTEMD_UNIT") != "ssh.service":
        raise ValueError("Only SSH service events are accepted")

    hostname = str(record["_HOSTNAME"]).strip()
    boot_id = str(record["_BOOT_ID"]).strip()
    message = str(record["MESSAGE"]).strip()

    if not hostname or not boot_id or not message:
        raise ValueError("Linux event contains empty required fields")

    try:
        microseconds = int(record["_SOURCE_REALTIME_TIMESTAMP"])

        if microseconds <= 0:
            raise ValueError("Timestamp must be positive")

        timestamp = datetime.fromtimestamp(
            microseconds / 1_000_000,
            tz=timezone.utc,
        )

    except (ValueError, TypeError, OverflowError, OSError) as error:
        raise ValueError("Invalid Linux journal timestamp") from error

    identity = (
        f"linux-journald:{hostname}:{boot_id}:"
        f"{microseconds}:{record.get('_PID', '')}:{message}"
    )

    return {
        "schema_version": "1.0",
        "event_id": str(uuid5(NAMESPACE_URL, identity)),
        "timestamp": timestamp.isoformat(),
        "source": "linux_journald",
        "hostname": hostname,
        "event_type": "linux_ssh_event",
        "src_ip": None,
        "message": message[:2048],
        "raw_event": dict(record),
    }
