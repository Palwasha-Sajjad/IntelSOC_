import re

IMPORTANT_FIELDS = (
    "new process name",
    "creator process name",
    "process command line",
)

FIELD_PATTERN = re.compile(
    r"(?i)\b(?:New Process Name|Creator Process Name|"
    r"Process Command Line|Token Elevation Type|"
    r"Mandatory Label|Creator Process ID|New Process ID)\s*:"
)


def select_mask_positions(text, max_masks=16):
    if max_masks < 1:
        raise ValueError("max_masks must be positive")

    words = list(re.finditer(r"\S+", text))
    if not words:
        return []

    limit = min(max_masks, len(words))
    selected = set()

    # Reserve some positions for general log coverage.
    coverage_count = min(4, limit)
    for i in range(coverage_count):
        index = round(
            i * (len(words) - 1) / max(1, coverage_count - 1)
        )
        selected.add(index)

    # Identify security-relevant Windows fields.
    matches = list(FIELD_PATTERN.finditer(text))
    field_positions = []

    for i, match in enumerate(matches):
        name = match.group().split(":")[0].strip().lower()
        if name not in IMPORTANT_FIELDS:
            continue

        end = (
            matches[i + 1].start()
            if i + 1 < len(matches)
            else len(text)
        )

        if name == "process command line":
            tail = re.search(
                r"\bToken Elevation Type indicates\b",
                text[match.end():end],
                re.I,
            )
            if tail:
                end = match.end() + tail.start()

        candidates = [
            j for j, word in enumerate(words)
            if word.start() >= match.end()
            and word.start() < end
        ]
        field_positions.append(candidates)

    # Round-robin selection avoids one field consuming every slot.
    depth = 0
    while len(selected) < limit and any(
        depth < len(field) for field in field_positions
    ):
        for field in field_positions:
            if depth < len(field) and len(selected) < limit:
                selected.add(field[depth])
        depth += 1

    # Fill remaining slots with evenly distributed positions.
    if len(selected) < limit:
        for i in range(len(words)):
            if len(selected) >= limit:
                break
            index = round(i * (len(words) - 1) / max(1, limit - 1))
            selected.add(index)

    # Ensure all available slots are filled when rounding overlaps.
    if len(selected) < limit:
        for index in range(len(words)):
            if len(selected) >= limit:
                break
            selected.add(index)

    return sorted(selected)

