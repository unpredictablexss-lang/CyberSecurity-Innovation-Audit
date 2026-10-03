from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any


@dataclass
class Finding:
    rule_id: str
    title: str
    vulnerability_type: str
    cwe: str
    severity: str
    confidence: str
    file_path: str
    line: int
    function: Optional[str]
    evidence: str
    explanation: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
