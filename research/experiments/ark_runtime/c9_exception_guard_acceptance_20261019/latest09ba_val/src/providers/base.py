"""Provider adapter contract for normalized multi-tool benchmark evidence.

Adapters only translate tool-native structured output into the project's
ToolRunResult schema. They do not execute scanners, validate vulnerabilities,
or perform runtime triggering.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, List, Optional

from src.benchmark.tool_result import ToolRunResult


@dataclass(frozen=True)
class AdapterContext:
    run_id: str
    target_id: str
    commit: str
    scope_files: int
    scope_loc: int
    elapsed_seconds: float
    peak_memory_mb: Optional[float] = None
    status: str = "completed"
    tool_version: Optional[str] = None
    limitations: List[str] = field(default_factory=list)


class ToolAdapter(ABC):
    provider: str

    @abstractmethod
    def normalize(self, payload: Any, context: AdapterContext) -> ToolRunResult:
        """Convert one tool-native report into the normalized result schema."""
        raise NotImplementedError


def first_cwe(value: Any) -> Optional[str]:
    """Best-effort extraction of one provisional CWE identifier."""
    if value is None:
        return None
    values = value if isinstance(value, list) else [value]
    for item in values:
        text = str(item)
        upper = text.upper()
        marker = "CWE-"
        index = upper.find(marker)
        if index >= 0:
            suffix = []
            for char in upper[index + len(marker):]:
                if char.isdigit():
                    suffix.append(char)
                elif suffix:
                    break
            if suffix:
                return f"CWE-{''.join(suffix)}"
    return None
