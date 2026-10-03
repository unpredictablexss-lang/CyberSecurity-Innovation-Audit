"""Normalized result schema for multi-tool benchmark comparisons.

This module records descriptive scanner output. It does not turn warnings into
validated vulnerabilities and intentionally contains no exploit or runtime
trigger logic.
"""

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


_ALLOWED_STATUSES = {"completed", "failed", "blocked"}
_ALLOWED_EVIDENCE_TYPES = {
    "pattern",
    "syntax",
    "dataflow",
    "control_flow",
    "symbolic",
    "historical",
    "runtime",
    "permission",
    "web_dynamic",
    "human_review",
    "unknown",
}


@dataclass(frozen=True)
class ToolDiagnostic:
    diagnostic_id: str
    provider: str
    evidence_type: str
    file: str
    line: Optional[int]
    column: Optional[int]
    rule_id: Optional[str]
    severity: str
    message: str
    candidate_cwe: Optional[str] = None
    confidence: str = "unassessed"

    def __post_init__(self) -> None:
        if not self.diagnostic_id.strip():
            raise ValueError("diagnostic_id must not be empty")
        if not self.provider.strip():
            raise ValueError("provider must not be empty")
        if self.evidence_type not in _ALLOWED_EVIDENCE_TYPES:
            raise ValueError(f"unsupported evidence_type: {self.evidence_type}")
        if self.line is not None and self.line < 1:
            raise ValueError("line must be >= 1 when provided")
        if self.column is not None and self.column < 1:
            raise ValueError("column must be >= 1 when provided")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ToolRunResult:
    schema_version: int
    run_id: str
    tool: str
    tool_version: str
    target_id: str
    commit: str
    scope_files: int
    scope_loc: int
    status: str
    elapsed_seconds: float
    peak_memory_mb: Optional[float] = None
    diagnostics: List[ToolDiagnostic] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError(f"unsupported schema_version: {self.schema_version}")
        if not self.run_id.strip():
            raise ValueError("run_id must not be empty")
        if not self.tool.strip():
            raise ValueError("tool must not be empty")
        if not self.target_id.strip():
            raise ValueError("target_id must not be empty")
        if not self.commit.strip():
            raise ValueError("commit must not be empty")
        if self.scope_files < 0:
            raise ValueError("scope_files must be >= 0")
        if self.scope_loc < 0:
            raise ValueError("scope_loc must be >= 0")
        if self.elapsed_seconds < 0:
            raise ValueError("elapsed_seconds must be >= 0")
        if self.peak_memory_mb is not None and self.peak_memory_mb < 0:
            raise ValueError("peak_memory_mb must be >= 0 when provided")
        if self.status not in _ALLOWED_STATUSES:
            raise ValueError(f"unsupported status: {self.status}")

    @property
    def diagnostic_count(self) -> int:
        return len(self.diagnostics)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "tool": self.tool,
            "tool_version": self.tool_version,
            "target_id": self.target_id,
            "commit": self.commit,
            "scope_files": self.scope_files,
            "scope_loc": self.scope_loc,
            "status": self.status,
            "elapsed_seconds": self.elapsed_seconds,
            "peak_memory_mb": self.peak_memory_mb,
            "diagnostic_count": self.diagnostic_count,
            "diagnostics": [item.to_dict() for item in self.diagnostics],
            "limitations": list(self.limitations),
            "interpretation": (
                "Descriptive scanner evidence only. Diagnostics are candidates/evidence, "
                "not validated vulnerabilities; an empty diagnostic list is not proof of safety."
            ),
        }
