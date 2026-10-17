"""Normalized result schema for multi-tool benchmark comparisons.

This module records descriptive scanner output. It does not turn warnings into
validated vulnerabilities and intentionally contains no exploit or runtime
trigger logic.
"""

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional
import re


_ALLOWED_STATUSES = {"completed", "failed", "blocked"}
# v2 requires every diagnostic to name its source revision; v1 payloads had no
# such field, so they load with an empty hash and are reported as `unbound`.
_SUPPORTED_SCHEMA_VERSIONS = (1, 2)
_SOURCE_HASH = re.compile(r"[a-f0-9]{64}")
_CWE = re.compile(r"CWE-[0-9]+")
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
    symbol: Optional[str] = None
    # Contract v2. Required in v2 output, empty only on payloads migrated from v1
    # (which are then reported as `unbound` -- unknown, never "verified").
    source_sha256: str = ""
    # The mechanism CWE above answers *how* the boundary failed; these answer *what*
    # it can expose. Both optional, and neither replaces the other.
    consequence_impact: Optional[str] = None
    consequence_cwe: Optional[str] = None
    # Optional A-CCR-03 identity sidecar. Omitted for legacy v1/v2 payloads so
    # readers never mistake absent identity for a computed historical identity.
    finding_identity_id: Optional[str] = None
    occurrence_id: Optional[str] = None
    finding_identity: Optional[Dict[str, Any]] = None

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
        if self.symbol is not None and (not isinstance(self.symbol, str) or not self.symbol.strip()):
            raise ValueError("symbol must be non-empty when provided")
        if self.source_sha256 and not _SOURCE_HASH.fullmatch(self.source_sha256):
            raise ValueError("invalid source SHA-256")
        if self.consequence_impact is not None and (
                not isinstance(self.consequence_impact, str) or not self.consequence_impact.strip()):
            raise ValueError("consequence_impact must be non-empty when provided")
        if self.consequence_cwe is not None and not _CWE.fullmatch(self.consequence_cwe):
            raise ValueError("invalid consequence CWE identifier")
        for key, value in (("finding_identity_id", self.finding_identity_id),
                           ("occurrence_id", self.occurrence_id)):
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise ValueError(key + " must be non-empty when provided")
        if self.finding_identity is not None and not isinstance(self.finding_identity, dict):
            raise ValueError("finding_identity must be an object when provided")

    @property
    def source_binding(self) -> str:
        """`bound` when the diagnostic names a source revision, else `unbound`.

        `unbound` is unknown binding, not a passed check: a payload migrated from
        v1 carries no hash and must never be dressed up with one.
        """
        return "bound" if self.source_sha256 else "unbound"

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["source_binding"] = self.source_binding
        # Keep legacy payload shape byte-compatible when identity is absent.
        for key in ("finding_identity_id", "occurrence_id", "finding_identity"):
            if data.get(key) is None:
                data.pop(key, None)
        return data


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
    parsing: List[dict] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.schema_version not in _SUPPORTED_SCHEMA_VERSIONS:
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
        if self.schema_version == 2:
            unbound = [item.diagnostic_id for item in self.diagnostics if not item.source_sha256]
            if unbound:
                # A v2 producer must bind every diagnostic to a source revision.
                # Failing here is the point: the alternative is emitting an ID that
                # looks versioned while standing for no particular source.
                raise ValueError(
                    "schema_version 2 requires a source SHA-256 on every diagnostic: "
                    + ", ".join(sorted(unbound)[:5])
                )

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
            "parsing": self.parsing,
            "interpretation": (
                "Descriptive scanner evidence only. Diagnostics are candidates/evidence, "
                "not validated vulnerabilities; an empty diagnostic list is not proof of safety."
            ),
        }


def render_markdown(result: "ToolRunResult") -> str:
    lines = [
        "# Normalized Tool Run Result",
        "",
        "> Descriptive scanner evidence only; diagnostics are candidates/evidence, "
        "not validated vulnerabilities.",
        "",
        "## Run summary",
        "",
        f"- Run ID: {result.run_id}",
        f"- Tool: {result.tool}",
        f"- Tool version: {result.tool_version}",
        f"- Target ID: {result.target_id}",
        f"- Commit: {result.commit}",
        f"- Scope: {result.scope_files} files / {result.scope_loc} LOC",
        f"- Status: {result.status}",
        f"- Elapsed seconds: {result.elapsed_seconds:.6f}",
        f"- Peak memory MB: {result.peak_memory_mb if result.peak_memory_mb is not None else 'n/a'}",
        f"- Diagnostics: {result.diagnostic_count}",
        "",
        "## Diagnostics",
        "",
    ]
    if not result.diagnostics:
        lines.append("(none)")
    else:
        # Mechanism CWE and consequence are separate columns on purpose: they answer
        # different questions and one must not be read as the other.
        lines.append("| ID | File | Line | Severity | CWE (mechanism) | Consequence | Consequence CWE | Source | Message |")
        lines.append("|---|---|---:|---|---|---|---|---|---|")
        for item in result.diagnostics:
            consequence = item.consequence_impact or "-"
            lines.append(
                f"| {item.diagnostic_id} | {item.file} | "
                f"{item.line if item.line is not None else '-'} | {item.severity} | "
                f"{item.candidate_cwe or '-'} | {consequence} | "
                f"{item.consequence_cwe or '-'} | {item.source_binding} | {item.message} |"
            )
    lines.extend(["", "## Limitations", ""])
    for limitation in result.limitations:
        lines.append(f"- {limitation}")
    lines.append("")
    return "\n".join(lines)


def write_reports(
    result: "ToolRunResult",
    json_output: "Path",
    markdown_output: "Path",
) -> None:
    import json as _json

    json_output.parent.mkdir(parents=True, exist_ok=True)
    markdown_output.parent.mkdir(parents=True, exist_ok=True)
    json_output.write_text(
        _json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    markdown_output.write_text(render_markdown(result), encoding="utf-8")
