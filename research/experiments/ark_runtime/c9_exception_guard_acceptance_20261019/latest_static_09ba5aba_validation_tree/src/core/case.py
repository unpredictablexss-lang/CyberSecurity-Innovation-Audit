import hashlib
from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional

from src.core.evidence import Evidence


def make_case_id(title: str, root_cause: str, primary_location: Optional[str]) -> str:
    """Stable case id from identity fields, independent of absolute paths."""
    identity = "|".join([title, root_cause, primary_location or ""])
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]


def make_evidence_id(source: str, content: str) -> str:
    identity = "|".join([source, content])
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]


@dataclass
class VulnerabilityCase:
    """A deduplicated, evidence-backed vulnerability root cause.

    Upgrades a cluster of Findings into one reportable case carrying PoC,
    impact, affected versions, patch and Evidence. See architecture_2026.md
    section 12. ``report_status`` stays ``candidate`` until evidence supports a
    stronger state; do not treat a case as a validated vulnerability by default.
    """

    case_id: str
    title: str
    root_cause: str
    cwe: str
    severity: str = "unassessed"
    cve: Optional[str] = None
    primary_location: Optional[str] = None
    related_findings: List[str] = field(default_factory=list)
    source_to_sink_trace: List[str] = field(default_factory=list)
    trigger_conditions: str = ""
    poc: Optional[str] = None
    runtime_evidence: List[str] = field(default_factory=list)
    affected_modules: List[str] = field(default_factory=list)
    affected_versions: List[str] = field(default_factory=list)
    patch: Optional[str] = None
    patch_validation: str = "not_started"
    confidence: str = "unassessed"
    report_status: str = "candidate"
    evidence: List[Evidence] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
