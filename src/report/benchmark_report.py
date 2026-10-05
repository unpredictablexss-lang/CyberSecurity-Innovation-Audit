"""Historical benchmark summary report.

Aggregates the historical samples + root-cause hit matrix into one descriptive
summary: sample count, root-cause group and CWE distribution, runtime status,
own-scanner hits, the root-cause matrix, and which cells are miss / unknown. It
is a benchmark summary, never a vulnerability report, and validated_vulnerability
is always 0 here.
"""

from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

from src.benchmark.historical import HistoricalSample
from src.benchmark.root_cause_matrix import (
    RootCauseMatrix,
    ToolCandidate,
    build_root_cause_hit_matrix,
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
                "sample set (3) is too small and lacks negative ground truth. "
                "possible_hit/miss/unknown describe tool coverage, not vulnerability truth."
            ),
        }


def build_benchmark_report(
    samples: List[HistoricalSample],
    tool_candidates: Dict[str, Optional[List[ToolCandidate]]],
) -> BenchmarkSummaryReport:
    matrix = build_root_cause_hit_matrix(samples, tool_candidates)
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


def _own_scanner_status(matrix: RootCauseMatrix, tool: str) -> Dict[str, str]:
    return {
        row.sample_id: row.status
        for row in matrix.rows
        if row.tool == tool
    }


def render_markdown(report: BenchmarkSummaryReport) -> str:
    matrix = report.root_cause_matrix
    tools = sorted({row.tool for row in matrix.rows})
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
    lines.extend(["", "## Own scanner hit status", "", "| sample_id | own_text | own_ast |", "|---|---|---|"])
    for sample_id in sorted(own_text):
        lines.append(f"| {sample_id} | {own_text.get(sample_id, 'unknown')} | {own_ast.get(sample_id, 'unknown')} |")
    lines.extend(["", "## Root-cause hit matrix", ""])
    lines.append(_render_matrix_markdown(matrix))
    lines.extend(
        [
            "",
            "## Why no Precision/Recall",
            "",
            "- Only 3 samples; no adequate labeled negative ground-truth set.",
            "- possible_hit is region overlap, not a confirmed true positive.",
            "- miss on one tool is a blind-spot record, not a measured false negative.",
            "- Reporting raw hit / miss / unknown counts only.",
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
