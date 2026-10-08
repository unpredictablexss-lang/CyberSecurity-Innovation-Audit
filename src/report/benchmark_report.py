"""Historical benchmark summary report.

Aggregates the historical samples + root-cause hit matrix into one descriptive
summary: sample count, root-cause group and CWE distribution, runtime status,
own-scanner hits, the root-cause matrix, and which cells are miss / unknown. It
is a benchmark summary, never a vulnerability report, and validated_vulnerability
is always 0 here.
"""

from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Optional

from src.benchmark.historical import HistoricalSample
from src.benchmark.root_cause_matrix import (
    RootCauseMatrix,
    SampleToolRun,
    build_root_cause_hit_matrix,
    build_revision_hit_matrix,
)


@dataclass
class BenchmarkSummaryReport:
    sample_count: int
    root_cause_group_distribution: Dict[str, int]
    cwe_distribution: Dict[str, int]
    runtime_validation_by_sample: Dict[str, str]
    root_cause_matrix: RootCauseMatrix
    validated_vulnerability: int = 0

    def to_dict(self) -> Dict[str, object]:
        return {
            "title": "Historical Benchmark Summary Report",
            "sample_count": self.sample_count,
            "root_cause_group_distribution": self.root_cause_group_distribution,
            "cwe_distribution": self.cwe_distribution,
            "runtime_validation_by_sample": self.runtime_validation_by_sample,
            "root_cause_matrix": self.root_cause_matrix.to_dict(),
            "validated_vulnerability": self.validated_vulnerability,
            "interpretation": (
                "Benchmark summary only. No Precision/Recall is computed because the "
                f"sample set ({self.sample_count}) lacks adequate labeled controls. "
                "possible_hit/miss/unknown/not_applicable describe static region coverage, "
                "not vulnerability truth."
            ),
        }


def build_benchmark_report(
    samples: List[HistoricalSample],
    tool_candidates: Optional[Dict[str, object]] = None,
    *,
    runs: Optional[List[SampleToolRun]] = None,
    tools: Optional[List[str]] = None,
) -> BenchmarkSummaryReport:
    if runs is not None and tool_candidates is not None:
        raise ValueError("use either saved runs or legacy candidates, not both")
    if runs is not None:
        matrix = build_revision_hit_matrix(samples, runs, tools=tools)
    elif tool_candidates is not None:
        # Compatibility for callers comparing one explicitly supplied revision.
        matrix = build_root_cause_hit_matrix(samples, tool_candidates)
    else:
        matrix = build_revision_hit_matrix(samples, [], tools=tools)
    groups = Counter(sample.root_cause_group for sample in samples)
    cwes = Counter(sample.weakness for sample in samples)
    runtime = {sample.sample_id: sample.runtime_replay_status for sample in samples}
    return BenchmarkSummaryReport(
        sample_count=len(samples),
        root_cause_group_distribution=dict(sorted(groups.items())),
        cwe_distribution=dict(sorted(cwes.items())),
        runtime_validation_by_sample=runtime,
        root_cause_matrix=matrix,
        validated_vulnerability=0,
    )


def _own_scanner_status(matrix: RootCauseMatrix, tool: str) -> dict:
    return {
        (row.sample_id, row.revision): row.status
        for row in matrix.rows
        if row.tool == tool
    }


def render_markdown(report: BenchmarkSummaryReport) -> str:
    matrix = report.root_cause_matrix
    own_text = _own_scanner_status(matrix, "own_text")
    own_ast = _own_scanner_status(matrix, "own_ast")

    lines = [
        "# Historical Benchmark Summary Report",
        "",
        "> Benchmark summary only; not a vulnerability report. No Precision/Recall is "
        "computed, and validated_vulnerability is 0.",
        "",
        "## Samples",
        "",
        f"- Historical sample count: {report.sample_count}",
        "",
        "### root_cause_group distribution",
        "",
    ]
    for group, count in report.root_cause_group_distribution.items():
        lines.append(f"- {group}: {count}")
    lines.extend(["", "### CWE distribution", ""])
    for cwe, count in report.cwe_distribution.items():
        lines.append(f"- {cwe}: {count}")
    lines.extend(["", "### runtime_validation by sample", ""])
    for sample_id, status in report.runtime_validation_by_sample.items():
        lines.append(f"- {sample_id}: {status}")
    lines.extend(["", "## Own scanner hit status", "", "| sample_id | revision | own_text | own_ast |", "|---|---|---|---|"])
    for key in sorted({(row.sample_id, row.revision) for row in matrix.rows}):
        sample_id, revision = key
        lines.append(f"| {sample_id} | {revision} | {own_text.get(key, 'unknown')} | {own_ast.get(key, 'unknown')} |")
    lines.extend(["", "## Root-cause hit matrix", ""])
    lines.append(_render_matrix_markdown(matrix))
    lines.extend(["", "## Saved run provenance and limitations", ""])
    for row in matrix.rows:
        if row.source_report:
            lines.extend([
                f"- {row.sample_id} / {row.revision} / {row.tool}: {row.status}",
                f"  - Commit: `{row.commit}`; run ID: `{row.run_id}`",
                f"  - Source: `{row.source_report}`; SHA-256: `{row.source_sha256}`",
                f"  - Version: `{row.tool_version}`; execution: `{row.run_status}`; "
                f"scope: {row.scope_files} files / {row.scope_loc} LOC",
            ])
            for limitation in row.limitations:
                lines.append(f"  - Limitation: {limitation}")
            for snapshot in row.source_snapshots:
                lines.append(f"  - Pinned source: `{snapshot['file']}` at `{snapshot['commit']}`; "
                             f"AST: {snapshot['status']}; SHA-256: `{snapshot['sha256']}`; "
                             f"issues: {snapshot.get('issues', [])}; {snapshot.get('reason', '')}")
        if row.reason:
            lines.append(f"- {row.sample_id} / {row.revision} / {row.tool}: {row.reason}")
    lines.extend(
        [
            "",
            "## Why no Precision/Recall",
            "",
            f"- {report.sample_count} samples; no adequate labeled negative ground-truth set.",
            "- possible_hit is region overlap, not a confirmed true positive.",
            "- miss on one tool is a blind-spot record, not a measured false negative.",
            "- Reporting possible_hit / miss / unknown / not_applicable only.",
            "",
            "## Validated vulnerability",
            "",
            f"validated_vulnerability = {report.validated_vulnerability}",
            "",
        ]
    )
    return "\n".join(lines)


def _render_matrix_markdown(matrix: RootCauseMatrix) -> str:
    from src.benchmark.root_cause_matrix import render_markdown as _matrix_md

    return _matrix_md(matrix).strip()


def write_reports(
    report: BenchmarkSummaryReport,
    json_output,
    markdown_output,
) -> None:
    import json

    json_output.parent.mkdir(parents=True, exist_ok=True)
    markdown_output.parent.mkdir(parents=True, exist_ok=True)
    json_output.write_text(
        json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    markdown_output.write_text(render_markdown(report), encoding="utf-8")
