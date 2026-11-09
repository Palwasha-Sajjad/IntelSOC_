"""Small independent rule dispatcher; each rule owns its event state."""
from dataclasses import dataclass
from typing import Callable, Mapping, Sequence


@dataclass(frozen=True)
class RuleRunner:
    rule_id: str
    run: Callable[[], Mapping[str, int]]


@dataclass(frozen=True)
class RuleOutcome:
    rule_id: str
    result: Mapping[str, int] | None
    error: Exception | None


def run_registered_rules(rules: Sequence[RuleRunner]) -> list[RuleOutcome]:
    """A failed rule must not prevent another rule from running."""
    seen = set()
    for rule in rules:
        if not rule.rule_id or rule.rule_id in seen:
            raise ValueError("Rule IDs must be non-empty and unique")
        seen.add(rule.rule_id)

    outcomes = []
    for rule in rules:
        try:
            outcomes.append(RuleOutcome(rule.rule_id, rule.run(), None))
        except Exception as error:
            outcomes.append(RuleOutcome(rule.rule_id, None, error))
    return outcomes
