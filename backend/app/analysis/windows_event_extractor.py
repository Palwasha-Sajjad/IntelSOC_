import ipaddress
import re
from dataclasses import dataclass
from typing import Any


FAILED_LOGON_EVENT_ID = 4625
SECURITY_CHANNEL = "Security"
SECURITY_PROVIDER = "Microsoft-Windows-Security-Auditing"


@dataclass(frozen=True)
class WindowsFailedLogonEvidence:
    """Evidence extracted from one genuine Windows Security 4625 event."""

    target_user: str | None
    target_domain: str | None
    source_ip: str | None
    source_port: int | None
    logon_type: int | None
    status: str | None
    substatus: str | None
    process_name: str | None
    workstation_name: str | None


def is_windows_failed_logon(record: dict[str, Any]) -> bool:
    """
    Return True only for the Security-Auditing 4625 event.

    Event ID alone is not sufficient because the same numeric EventID
    can appear under other Windows providers/channels.
    """

    try:
        event_id = int(record.get("EventID"))
    except (TypeError, ValueError):
        return False

    channel = str(record.get("Channel") or "").strip()
    provider = str(record.get("ProviderName") or "").strip()

    return (
        event_id == FAILED_LOGON_EVENT_ID
        and channel.casefold() == SECURITY_CHANNEL.casefold()
        and provider.casefold() == SECURITY_PROVIDER.casefold()
    )


def extract_windows_failed_logon(
    record: dict[str, Any],
) -> WindowsFailedLogonEvidence | None:
    """
    Extract useful evidence from one Windows Security event.

    The collector's raw event is never mutated. For Event 4625,
    StringInserts is preferred because it follows the Windows event
    field order. Message parsing is only a narrow fallback when those
    inserts are unavailable.
    """

    if not is_windows_failed_logon(record):
        return None

    inserts = record.get("StringInserts")

    if isinstance(inserts, list):
        structured = _extract_from_string_inserts(inserts)

        # A short or incomplete insert list should not prevent fallback
        # extraction from the preserved event message.
        if _has_useful_evidence(structured):
            return structured

    return _extract_from_message(str(record.get("Message") or ""))


def _extract_from_string_inserts(
    inserts: list[Any],
) -> WindowsFailedLogonEvidence:
    """
    Map Event 4625 insertion strings using the documented field order.

    Relevant positions:
      5  TargetUserName
      6  TargetDomainName
      7  Status
      9  SubStatus
      10 LogonType
      13 WorkstationName
      18 ProcessName
      19 IpAddress
      20 IpPort
    """

    return WindowsFailedLogonEvidence(
        target_user=_value_at(inserts, 5),
        target_domain=_value_at(inserts, 6),
        source_ip=_normalize_ip(_value_at(inserts, 19)),
        source_port=_parse_int(_value_at(inserts, 20)),
        logon_type=_parse_int(_value_at(inserts, 10)),
        status=_value_at(inserts, 7),
        substatus=_value_at(inserts, 9),
        process_name=_value_at(inserts, 18),
        workstation_name=_value_at(inserts, 13),
    )


def _extract_from_message(
    message: str,
) -> WindowsFailedLogonEvidence:
    target_section = _section(
        message,
        "Account For Which Logon Failed:",
        "Failure Information:",
    )

    return WindowsFailedLogonEvidence(
        target_user=_match_value(
            target_section,
            r"Account Name:\s*([^\r\n]+)",
        ),
        target_domain=_match_value(
            target_section,
            r"Account Domain:\s*([^\r\n]+)",
        ),
        source_ip=_normalize_ip(
            _match_value(
                message,
                r"Source Network Address:\s*([^\r\n]+)",
            )
        ),
        source_port=_parse_int(
            _match_value(
                message,
                r"Source Port:\s*([^\r\n]+)",
            )
        ),
        logon_type=_parse_int(
            _match_value(
                message,
                r"Logon Type:\s*([^\r\n]+)",
            )
        ),
        status=_match_value(
            message,
            r"Status:\s*([^\r\n]+)",
        ),
        substatus=_match_value(
            message,
            r"Sub Status:\s*([^\r\n]+)",
        ),
        process_name=_match_value(
            message,
            r"Caller Process Name:\s*([^\r\n]+)",
        ),
        workstation_name=_match_value(
            message,
            r"Workstation Name:\s*([^\r\n]+)",
        ),
    )


def _value_at(values: list[Any], index: int) -> str | None:
    if index >= len(values):
        return None

    return _clean_optional(values[index])


def _clean_optional(value: Any) -> str | None:
    if value is None:
        return None

    text = str(value).strip()

    if not text or text == "-":
        return None

    return text


def _parse_int(value: Any) -> int | None:
    cleaned = _clean_optional(value)

    if cleaned is None:
        return None

    try:
        return int(cleaned, 10)
    except ValueError:
        return None


def _normalize_ip(value: Any) -> str | None:
    cleaned = _clean_optional(value)

    if cleaned is None:
        return None

    try:
        return str(ipaddress.ip_address(cleaned))
    except ValueError:
        return None


def _match_value(text: str, pattern: str) -> str | None:
    match = re.search(
        pattern,
        text,
        flags=re.IGNORECASE,
    )

    if not match:
        return None

    return _clean_optional(match.group(1))


def _section(
    text: str,
    start_marker: str,
    end_marker: str,
) -> str:
    pattern = (
        re.escape(start_marker)
        + r"(.*?)"
        + re.escape(end_marker)
    )

    match = re.search(
        pattern,
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )

    return match.group(1) if match else ""


def _has_useful_evidence(
    evidence: WindowsFailedLogonEvidence,
) -> bool:
    return any(
        value is not None
        for value in (
            evidence.target_user,
            evidence.target_domain,
            evidence.source_ip,
            evidence.source_port,
            evidence.logon_type,
            evidence.status,
            evidence.substatus,
            evidence.process_name,
            evidence.workstation_name,
        )
    )
