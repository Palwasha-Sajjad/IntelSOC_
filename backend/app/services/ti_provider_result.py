from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ProviderResult:
    provider: str
    indicator_type: str
    indicator_value: str
    verdict: str
    lookup_status: str
    confidence: int | None = None
    details: dict[str, Any] = field(default_factory=dict)
