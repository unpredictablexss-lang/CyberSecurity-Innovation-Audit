from dataclasses import dataclass, asdict
from typing import Any, Dict, Optional


@dataclass
class Evidence:
    """A traceable piece of evidence supporting a vulnerability claim.

    ``type`` follows architecture_2026.md: rule | ast | cfg | dataflow | taint
    | runtime | git | llm. Every conclusion should trace back to Evidence.
    """

    evidence_id: str
    type: str
    source: str
    location: Optional[str] = None
    content: str = ""
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
