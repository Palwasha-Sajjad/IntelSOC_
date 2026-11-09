"""WIN-009: high-confidence suspicious scheduled-task creation/update.

Requires genuine-shaped Windows Security 4698/4702 with structured task XML.
Routine task creation, updates, or root-level names are not inherently malicious.
The source raw_event is never mutated.
"""
from datetime import datetime
import re
from typing import Any, Mapping
from xml.etree import ElementTree

from app.analysis.detection_candidate import DetectionCandidate

RULE_ID = "RULE-WIN-009"
RULE_NAME = "Suspicious Scheduled Task Command"
PROVIDER = "microsoft-windows-security-auditing"
EVENT_IDS = {4698, 4702}
MAX_XML_LENGTH = 65536

# Only strong indicators in the actual task Exec action. This is intentionally
# narrow: task creation alone, generic PowerShell, and ordinary updates do not
# produce high-severity incidents.
ENCODED_PS = re.compile(
    r"(?i)(?:^|\s)[-/](?:encodedcommand|enc)(?::|\s|$)"
)
POWERSHELL_EXE = re.compile(r"(?i)(?:^|[\\/])(?:powershell|pwsh)(?:\.exe)?$")
MSHTA_EXE = re.compile(r"(?i)(?:^|[\\/])mshta(?:\.exe)?$")
URL = re.compile(r"(?i)https?://[^\s\"']+")


def _child_text(root: ElementTree.Element, path: str) -> str:
    # Match XML local names so both default-namespaced and plain task XML work.
    nodes = [root]
    for part in path.split("/"):
        next_nodes = []
        for node in nodes:
            next_nodes.extend(
                item for item in node
                if item.tag.split("}")[-1] == part
            )
        nodes = next_nodes
        if not nodes:
            return ""
    return (nodes[0].text or "").strip()


def _suspicious_exec(task_xml: str) -> bool:
    if len(task_xml) > MAX_XML_LENGTH or "<!DOCTYPE" in task_xml.upper() or "<!ENTITY" in task_xml.upper():
        return False
    try:
        root = ElementTree.fromstring(task_xml)
    except ElementTree.ParseError:
        return False
    if root.tag.split("}")[-1] != "Task":
        return False

    # Only executable task actions count. A matching tag embedded in
    # registration metadata or unrelated XML is not evidence of execution.
    action_sections = [
        child for child in root
        if child.tag.split("}")[-1] == "Actions"
    ]
    for section in action_sections:
        for action in section:
            if action.tag.split("}")[-1] != "Exec":
                continue
            command = _child_text(action, "Command")
            arguments = _child_text(action, "Arguments")
            if not command:
                continue
            executable = command.strip().strip('"').replace("/", "\\").split("\\")[-1]
            if POWERSHELL_EXE.fullmatch(executable) and ENCODED_PS.search(arguments):
                return True
            if MSHTA_EXE.fullmatch(executable) and URL.search(arguments):
                return True
    return False


def detect_suspicious_scheduled_task(
    event: Mapping[str, Any],
) -> DetectionCandidate | None:
    raw = event.get("raw_event")
    if not isinstance(raw, dict):
        return None
    try:
        number = int(raw.get("EventID"))
    except (ValueError, TypeError):
        return None
    if (
        number not in EVENT_IDS
        or str(raw.get("Channel") or "").strip().casefold() != "security"
        or str(raw.get("ProviderName") or "").strip().casefold() != PROVIDER
    ):
        return None

    # Both 4698/4702: actor SID, actor user, domain, logon ID,
    # TaskName, TaskContent or TaskContentNew. Later version fields append.
    inserts = raw.get("StringInserts")
    if not isinstance(inserts, list) or len(inserts) < 6:
        return None
    task_name = str(inserts[4] or "").strip()
    task_xml = inserts[5]
    if (
        not task_name.startswith("\\")
        or task_name == "\\"
        or not isinstance(task_xml, str)
        or not task_xml.strip()
        or not _suspicious_exec(task_xml)
    ):
        return None

    stored_id = str(event.get("event_id") or "").strip()
    device_id = str(event.get("device_id") or "").strip()
    dt = event.get("event_time")
    if not stored_id or not device_id or not isinstance(dt, datetime) or dt.tzinfo is None:
        return None

    return DetectionCandidate(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        severity="high",
        device_id=device_id,
        grouping_basis="device_event",
        event_ids=(stored_id,),
        event_count=1,
        window_start=dt,
        window_end=dt,
    )
