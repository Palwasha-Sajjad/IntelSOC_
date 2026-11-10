import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlsplit
from xml.etree import ElementTree

from app.analysis.windows_event_extractor import extract_windows_failed_logon
from app.linux_src_ip import extract_linux_source_ip


_WINDOWS_SECURITY_PROVIDER = "microsoft-windows-security-auditing"
_POWERSHELL_PROVIDER = "microsoft-windows-powershell"
_POWERSHELL_CHANNEL = "microsoft-windows-powershell/operational"
_URL_RE = re.compile(r"(?i)https?://[^\s\"'<>]+")
_LOCAL_SUFFIXES = {"local", "localhost", "internal", "lan", "home"}


@dataclass(frozen=True, order=True)
class ThreatIndicator:
    indicator_type: str
    value: str


def normalize_public_ip(value: Any) -> str | None:
    """Return a canonical globally routable IP, otherwise None."""

    text = str(value or "").strip().strip("[]")
    if not text or text in {"-", "?"}:
        return None

    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None

    if not address.is_global:
        return None

    return str(address)


def normalize_domain(value: Any) -> str | None:
    """Return a conservative canonical external domain, otherwise None."""

    text = str(value or "").strip().rstrip(".").casefold()
    if not text or len(text) > 253:
        return None

    try:
        ipaddress.ip_address(text)
        return None
    except ValueError:
        pass

    try:
        ascii_domain = text.encode("idna").decode("ascii").casefold()
    except UnicodeError:
        return None

    labels = ascii_domain.split(".")
    if len(labels) < 2 or any(not label or len(label) > 63 for label in labels):
        return None

    label_re = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    if any(label_re.fullmatch(label) is None for label in labels):
        return None

    tld = labels[-1]
    if tld in _LOCAL_SUFFIXES or (not tld.startswith("xn--") and not tld.isalpha()):
        return None

    return ascii_domain


def extract_indicators_from_event(
    event: Mapping[str, Any],
) -> tuple[ThreatIndicator, ...]:
    """Extract only evidence-backed TI indicators from one stored event."""

    raw = event.get("raw_event")
    if not isinstance(raw, dict):
        return ()

    found: set[ThreatIndicator] = set()

    source_ip = _extract_source_ip(event, raw)
    if source_ip is not None:
        found.add(ThreatIndicator("ip", source_ip))

    for domain in _extract_domains(raw):
        found.add(ThreatIndicator("domain", domain))

    return tuple(sorted(found))


def _extract_source_ip(
    event: Mapping[str, Any],
    raw: dict[str, Any],
) -> str | None:
    source = str(event.get("source") or "").strip().casefold()

    if source.startswith("linux_"):
        evidence_ip = extract_linux_source_ip(raw)
        return normalize_public_ip(evidence_ip)

    if source != "windows_eventlog":
        return None

    if not _is_windows_security(raw):
        return None

    event_id = _event_id(raw)
    inserts = raw.get("StringInserts")

    if event_id == 4625:
        evidence = extract_windows_failed_logon(raw)
        return normalize_public_ip(evidence.source_ip if evidence else None)

    if not isinstance(inserts, list):
        return None

    # 4624: IpAddress is insertion field 18.
    if event_id == 4624 and len(inserts) >= 19:
        return normalize_public_ip(inserts[18])

    # 4648: IpAddress is insertion field 12.
    if event_id == 4648 and len(inserts) == 14:
        return normalize_public_ip(inserts[12])

    return None


def _extract_domains(raw: dict[str, Any]) -> set[str]:
    texts: list[str] = []

    event_id = _event_id(raw)

    if _is_windows_security(raw):
        inserts = raw.get("StringInserts")

        if event_id == 4688 and isinstance(inserts, list) and len(inserts) >= 9:
            command_line = inserts[8]
            if isinstance(command_line, str):
                texts.append(command_line)

        elif event_id in {4698, 4702} and isinstance(inserts, list) and len(inserts) >= 6:
            task_xml = inserts[5]
            if isinstance(task_xml, str):
                texts.extend(_task_exec_text(task_xml))

    elif (
        event_id == 4104
        and str(raw.get("Channel") or "").strip().casefold() == _POWERSHELL_CHANNEL
        and str(raw.get("ProviderName") or "").strip().casefold() == _POWERSHELL_PROVIDER
    ):
        inserts = raw.get("StringInserts")
        if isinstance(inserts, list) and len(inserts) == 5 and isinstance(inserts[2], str):
            texts.append(inserts[2])

    domains: set[str] = set()

    for text in texts:
        for match in _URL_RE.finditer(text):
            try:
                hostname = urlsplit(match.group(0)).hostname
            except ValueError:
                continue

            domain = normalize_domain(hostname)
            if domain is not None:
                domains.add(domain)

    return domains


def _task_exec_text(task_xml: str) -> list[str]:
    if (
        not task_xml.strip()
        or len(task_xml) > 65536
        or "<!DOCTYPE" in task_xml.upper()
        or "<!ENTITY" in task_xml.upper()
    ):
        return []

    try:
        root = ElementTree.fromstring(task_xml)
    except ElementTree.ParseError:
        return []

    if root.tag.split("}")[-1] != "Task":
        return []

    texts: list[str] = []

    for section in root:
        if section.tag.split("}")[-1] != "Actions":
            continue

        for action in section:
            if action.tag.split("}")[-1] != "Exec":
                continue

            for child in action:
                if child.tag.split("}")[-1] not in {"Command", "Arguments"}:
                    continue

                value = (child.text or "").strip()
                if value:
                    texts.append(value)

    return texts


def _is_windows_security(raw: Mapping[str, Any]) -> bool:
    return (
        str(raw.get("Channel") or "").strip().casefold() == "security"
        and str(raw.get("ProviderName") or "").strip().casefold()
        == _WINDOWS_SECURITY_PROVIDER
    )


def _event_id(raw: Mapping[str, Any]) -> int | None:
    try:
        return int(raw.get("EventID"))
    except (TypeError, ValueError):
        return None
