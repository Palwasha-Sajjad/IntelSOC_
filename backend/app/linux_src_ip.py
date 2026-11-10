import ipaddress
import re
from typing import Any


_FIELD_CANDIDATES = (
    "_REMOTE_ADDR",
    "REMOTE_ADDR",
    "RHOST",
    "rhost",
)

_MESSAGE_PATTERNS = (
    re.compile(r"(?i)(?:^|\s)rhost=(?P<ip>\[[^\]]+\]|[^\s;]+)"),
    re.compile(r"(?i)\bfrom\s+(?P<ip>\[[^\]]+\]|[^\s;]+)"),
)


def _validated_ip(value: Any) -> str | None:
    text = str(value or "").strip().strip("[]").rstrip(",;")
    if not text or text in {"-", "?"}:
        return None

    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None

    if address.is_unspecified:
        return None

    return str(address)


def extract_linux_source_ip(record: dict) -> str | None:
    """Return a validated source IP only when original Linux evidence contains it."""

    if not isinstance(record, dict):
        return None

    for field in _FIELD_CANDIDATES:
        source_ip = _validated_ip(record.get(field))
        if source_ip is not None:
            return source_ip

    message = str(record.get("MESSAGE") or "")

    for pattern in _MESSAGE_PATTERNS:
        match = pattern.search(message)
        if match is None:
            continue

        source_ip = _validated_ip(match.group("ip"))
        if source_ip is not None:
            return source_ip

    return None
