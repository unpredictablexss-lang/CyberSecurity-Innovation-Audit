"""Tool capability matrix from normalized multi-tool reports.

Aggregates descriptive per-tool statistics (diagnostic count, distinct CWE
coverage, evidence-type distribution, elapsed time, peak memory). It computes
no Precision/Recall/F1 because there is no adequate labeled ground-truth set.
"""

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.benchmark.compare import load_normalized_report, validate_comparable_runs


@dataclass
class ToolMatrixRow:
    tool: str
    diagnostic_count: int
    cwe_count: int
    evidence_types: Dict[str, int]
    elapsed_seconds: float
    peak_memory_mb: Optional[float]


@dataclass
class ToolCapabilityMatrix:
    target_id: str
    rows: List[ToolMatrixRow] = field(default_factory=list)
    commit: str = ""
    scope_files: int = 0
    scope_loc: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_id": self.target_id,
            "commit": self.commit,
            "scope_files": self.scope_files,
            "scope_loc": self.scope_loc,
            "rows": [asdict(row) for row in self.rows],
            "interpretation": (
                "Descriptive per-tool capability summary only. Diagnostic count is not a "
                "vulnerability count, CWE coverage is provisional per-tool labeling, and no "
                "Precision/Recall/F1 is computed without an adequate labeled ground-truth set."
            ),
        }


def build_tool_matrix(report_paths: List[Path]) -> ToolCapabilityMatrix:
    if not report_paths:
        raise ValueError("at least one normalized tool report is required")

    runs = [load_normalized_report(path.resolve()) for path in report_paths]
    validate_comparable_runs(runs)
    reference_target = runs[0]["target_id"]

    rows: List[ToolMatrixRow] = []
    for run in runs:
        diagnostics = [
            item for item in run.get("diagnostics", []) if isinstance(item, dict)
        ]
        cwes = {
            str(item["candidate_cwe"])
            for item in diagnostics
            if item.get("candidate_cwe")
        }
        evidence_types: Dict[str, int] = {}
        for item in diagnostics:
            key = str(item.get("evidence_type", "unknown"))
            evidence_types[key] = evidence_types.get(key, 0) + 1
        peak = run.get("peak_memory_mb")
        rows.append(
            ToolMatrixRow(
                tool=str(run["tool"]),
                diagnostic_count=len(diagnostics),
                cwe_count=len(cwes),
                evidence_types=dict(sorted(evidence_types.items())),
                elapsed_seconds=float(run["elapsed_seconds"]),
                peak_memory_mb=float(peak) if peak is not None else None,
            )
        )

    return ToolCapabilityMatrix(
        target_id=str(reference_target),
        rows=sorted(rows, key=lambda row: row.tool),
        commit=str(runs[0]["commit"]), scope_files=int(runs[0]["scope_files"]),
        scope_loc=int(runs[0]["scope_loc"]),
    )


def render_markdown(result: ToolCapabilityMatrix) -> str:
    lines = [
        "# Tool Capability Matrix",
        "",
        "> Descriptive capability summary only; diagnostics are candidates/evidence, "
        "not validated vulnerabilities.",
        "",
        f"## Target ID: {result.target_id}",
        f"- Commit: `{result.commit}`",
        f"- Scope: {result.scope_files} files / {result.scope_loc} LOC",
        "",
        "| Tool | Diagnostics | Distinct CWEs | Evidence types | Seconds | Peak MB |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for row in result.rows:
        peak = f"{row.peak_memory_mb:.2f}" if row.peak_memory_mb is not None else "n/a"
        evidence = ", ".join(
            f"{key}:{value}" for key, value in row.evidence_types.items()
        ) or "(none)"
        lines.append(
            f"| {row.tool} | {row.diagnostic_count} | {row.cwe_count} | "
            f"{evidence} | {row.elapsed_seconds:.6f} | {peak} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation limits",
            "",
            "- No Precision/Recall/F1 is computed.",
            "- CWE coverage is provisional and not re-verified against root cause.",
            "- Diagnostic count is not a vulnerability count.",
            "",
        ]
    )
    return "\n".join(lines)


def write_reports(
    result: ToolCapabilityMatrix,
    json_output: Path,
    markdown_output: Path,
) -> None:
    json_output.parent.mkdir(parents=True, exist_ok=True)
    markdown_output.parent.mkdir(parents=True, exist_ok=True)
    json_output.write_text(
        json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    markdown_output.write_text(render_markdown(result), encoding="utf-8")
