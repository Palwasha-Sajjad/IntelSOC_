from datetime import datetime
from uuid import NAMESPACE_URL, uuid5


def normalize_windows_event(record: dict) -> dict:
    """Convert a Windows Event Log record to IntelSOC's event schema."""

    required = (
        "Computer",
        "Channel",
        "EventRecordID",
        "EventID",
        "TimeCreated",
        "ProviderName",
    )

    for field in required:
        if field not in record:
            raise ValueError(f"Missing Windows event field: {field}")

    # Keep the original timezone information.
    timestamp = datetime.strptime(
        record["TimeCreated"],
        "%Y-%m-%d %H:%M:%S %z",
    )

    message = str(record.get("Message") or "").strip()

    if not message:
        message = "[No event message available]"

    # Same Windows record always produces the same UUID.
    identity = (
        f"windows-eventlog:"
        f"{record['Computer'].lower()}:"
        f"{record['Channel'].lower()}:"
        f"{record['EventRecordID']}"
    )

    return {
        "schema_version": "1.0",
        "event_id": str(uuid5(NAMESPACE_URL, identity)),
        "timestamp": timestamp.isoformat(),
        "source": "windows_eventlog",
        "hostname": record["Computer"],
        "event_type": f"windows_{record['Channel'].lower()}_event",
        "src_ip": None,
        "message": (
            f"EventID={record['EventID']} "
            f"Provider={record['ProviderName']}: "
            f"{message}"
        ),
    }
