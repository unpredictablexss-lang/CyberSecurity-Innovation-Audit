"""Detector-local proposed data types.

This module is an explicitly proposed implementation for pre-freeze experiments.
It is not the shared OHScanner contract and must not be treated as an API that
exists on main. Shared frontend/IR/integration ownership remains with the
project owner.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Tuple


ALLOWED_PARSE_STATUSES = {"complete", "partial", "failed", "not_run"}
ALLOWED_RUN_STATUSES = {"completed", "failed", "blocked"}


@dataclass(frozen=True)
class ProposedScanRequest:
    """Minimal provenance needed by the detector-local prototype."""

    request_id: str
    target_id: str
    repository: str
    commit: str
    snapshot_sha256: str
    profile_id: str


@dataclass(frozen=True)
class ProposedScanContext:
    """Read-only, detector-local context for fixture experiments."""

    request: ProposedScanRequest
    model_version: str = "cpp-local-proposed-v1"
    deadline_seconds: Optional[float] = None


@dataclass(frozen=True)
class ProposedSourceUnit:
    """SourceUnit-shaped fixture input; not a shared SourceUnit implementation."""

    path: str
    language: str
    sha256: str
    text: str
    parse_status: str
    parse_issues: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.parse_status not in ALLOWED_PARSE_STATUSES:
            raise ValueError(f"unsupported parse_status: {self.parse_status}")


@dataclass(frozen=True)
class ProposedDiagnostic:
    """Candidate evidence plus detector-local explanatory sidecar fields."""

    diagnostic_id: str
    provider: str
    evidence_type: str
    file: str
    line: int
    column: int
    rule_id: str
    severity: str
    message: str
    candidate_cwe: str
    confidence: str
    symbol: str
    explanation: str
    source_sha256: str
    limitations: Tuple[str, ...] = ()
    constraints: Tuple[str, ...] = ()
    missing_obligations: Tuple[str, ...] = ()

    def sort_key(self) -> Tuple[str, int, int, str, str]:
        return (self.file, self.line, self.column, self.diagnostic_id, self.rule_id)

    def sidecar_dict(self) -> dict:
        return {
            "diagnostic_id": self.diagnostic_id,
            "source_sha256": self.source_sha256,
            "explanation": self.explanation,
            "limitations": list(self.limitations),
            "constraints": list(self.constraints),
            "missing_obligations": list(self.missing_obligations),
            "candidate_status": "candidate",
            "review_status": "unassessed",
            "validation_status": "not_run",
        }


@dataclass(frozen=True)
class ProposedCoverage:
    """Parsing coverage only; this is not benchmark match status."""

    file: str
    parse_status: str
    parse_issues: Tuple[str, ...] = ()
    analyzed: bool = False

    def to_parsing_entry(self) -> dict:
        return {"file": self.file, "status": self.parse_status}


@dataclass(frozen=True)
class ProposedDetectorRun:
    """DetectorRun-shaped local output for tests and mapping design."""

    detector_id: str
    version: str
    status: str
    diagnostics: Tuple[ProposedDiagnostic, ...]
    analyzed_files: Tuple[str, ...]
    coverage: Tuple[ProposedCoverage, ...]
    limitations: Tuple[str, ...]
    elapsed_seconds: float
    scope_files: int
    scope_loc: int
    failure_kind: Optional[str] = None
    missing_obligations: Tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.status not in ALLOWED_RUN_STATUSES:
            raise ValueError(f"unsupported run status: {self.status}")
        if self.elapsed_seconds < 0:
            raise ValueError("elapsed_seconds must be >= 0")
