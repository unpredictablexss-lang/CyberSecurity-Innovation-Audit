"""Descriptive comparison of normalized multi-tool static-analysis reports.

This module compares already-normalized ToolRunResult JSON files. It does not
execute scanners, trigger code paths, or make vulnerability/exploitability
verdicts.
"""

import json
from dataclasses import dataclass, field
from itertools import combinations
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Set, Tuple


Location = Tuple[str, int]


@dataclass(frozen=True)
class ToolComparisonSummary:
    tool: str
    tool_version: str
    # Named per tool because contract v2 changed diagnostic_id values: two runs
    # carrying different versions are not carrying the same kind of ID.
    schema_version: int
    run_id: str
    diagnostic_count: int
    location_count: int
    elapsed_seconds: float
    peak_memory_mb: float | None
    evidence_type_counts: Dict[str, int]
    severity_counts: Dict[str, int]


@dataclass(frozen=True)
class PairwiseOverlap:
    left_tool: str
    right_tool: str
    exact_location_overlap: int
    left_only_locations: int
    right_only_locations: int


@dataclass
class MultiToolComparison:
    target_id: str
    commit: str
    scope_files: int
    scope_loc: int
    summaries: List[ToolComparisonSummary]
    pairwise_overlaps: List[PairwiseOverlap]
    locations_by_tool: Dict[str, List[Dict[str, Any]]]
    limitations: List[str]
    # tool -> schema_version of the transcript it contributed. Mixed values mean the
    # comparison crosses a schema change and the output has to say so.
    schema_versions: Dict[str, int] = field(default_factory=dict)

    def schema_versions_mixed(self) -> bool:
        return len(set(self.schema_versions.values())) > 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_id": self.target_id,
            "commit": self.commit,
            "scope_files": self.scope_files,
            "scope_loc": self.scope_loc,
            "schema_versions": self.schema_versions,
            "schema_versions_mixed": self.schema_versions_mixed(),
            "tools": [
                {
                    "tool": item.tool,
                    "tool_version": item.tool_version,
                    "schema_version": item.schema_version,
                    "run_id": item.run_id,
                    "diagnostic_count": item.diagnostic_count,
                    "location_count": item.location_count,
                    "elapsed_seconds": item.elapsed_seconds,
                    "peak_memory_mb": item.peak_memory_mb,
                    "evidence_type_counts": item.evidence_type_counts,
                    "severity_counts": item.severity_counts,
                }
                for item in self.summaries
            ],
            "pairwise_overlaps": [
                {
                    "left_tool": item.left_tool,
                    "right_tool": item.right_tool,
                    "exact_location_overlap": item.exact_location_overlap,
                    "left_only_locations": item.left_only_locations,
                    "right_only_locations": item.right_only_locations,
                }
                for item in self.pairwise_overlaps
            ],
            "locations_by_tool": self.locations_by_tool,
            "limitations": self.limitations,
            "interpretation": (
                "Descriptive location/evidence comparison only. Exact-location overlap is "
                "not a vulnerability vote, unique locations are not automatically false "
                "positives/negatives, and this report does not compute exploitability."
            ),
        }


_REQUIRED_RUN_FIELDS = {
    "schema_version",
    "run_id",
    "tool",
    "tool_version",
    "target_id",
    "commit",
    "scope_files",
    "scope_loc",
    "status",
    "elapsed_seconds",
    "diagnostics",
}


def load_normalized_report(path: Path) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"normalized report must contain a JSON object: {path}")
    missing = sorted(_REQUIRED_RUN_FIELDS - set(data))
    if missing:
        raise ValueError(
            f"normalized report missing fields ({path}): {', '.join(missing)}"
        )
    if data["schema_version"] not in (1, 2):
        raise ValueError(
            f"unsupported normalized report schema_version ({path}): "
            f"{data['schema_version']}"
        )
    if data["status"] != "completed":
        raise ValueError(
            f"tool run is not completed ({path}): status={data['status']}"
        )
    if not isinstance(data["diagnostics"], list):
        raise ValueError(f"diagnostics must be a list: {path}")
    return data


def _diagnostic_locations(run: Mapping[str, Any]) -> Set[Location]:
    locations: Set[Location] = set()
    for diagnostic in run.get("diagnostics", []):
        if not isinstance(diagnostic, Mapping):
            continue
        file = str(diagnostic.get("file", "") or "")
        line = diagnostic.get("line")
        if not file or line is None:
            continue
        try:
            line_number = int(line)
        except (TypeError, ValueError):
            continue
        if line_number >= 1:
            locations.add((file, line_number))
    return locations


def _count_field(
    diagnostics: Iterable[Mapping[str, Any]],
    field: str,
    default: str = "unknown",
) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for diagnostic in diagnostics:
        key = str(diagnostic.get(field, "") or default)
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def _location_rows(
    run: Mapping[str, Any],
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for diagnostic in run.get("diagnostics", []):
        if not isinstance(diagnostic, Mapping):
            continue
        rows.append(
            {
                "diagnostic_id": diagnostic.get("diagnostic_id"),
                "file": diagnostic.get("file"),
                "line": diagnostic.get("line"),
                "column": diagnostic.get("column"),
                "rule_id": diagnostic.get("rule_id"),
                "severity": diagnostic.get("severity"),
                "evidence_type": diagnostic.get("evidence_type"),
                "candidate_cwe": diagnostic.get("candidate_cwe"),
                # Mechanism and consequence stay separate columns here too.
                "consequence_impact": diagnostic.get("consequence_impact"),
                "consequence_cwe": diagnostic.get("consequence_cwe"),
                "source_binding": diagnostic.get("source_binding"),
            }
        )
    return rows


def _cross_version_note(versions: Mapping[str, int]) -> str | None:
    """Name a schema split instead of letting the comparison look homogeneous.

    Contract v2 moved `diagnostic_id` to include the source hash, so a v1 and a v2
    transcript use ID spaces that are not interchangeable. The comparison still
    runs -- refusing it would just push people to compare by hand -- but the output
    must record which tool spoke which version.
    """
    distinct = sorted(set(versions.values()))
    if len(distinct) < 2:
        return None
    rendered = ", ".join(f"{tool}=v{version}" for tool, version in sorted(versions.items()))
    return (
        f"CROSS-VERSION COMPARISON: schema versions differ ({rendered}); diagnostic_id "
        "values are not exchangeable across versions because v2 IDs include the source "
        "hash. Row counts and locations remain comparable, IDs do not."
    )


def validate_comparable_runs(runs: Sequence[Mapping[str, Any]]) -> None:
    """One analysis unit: same target, commit, scope and one run per tool.

    Schema versions are deliberately *not* a comparability condition: v1 and v2
    transcripts are compared, and the version split is named in the output.
    """
    if not runs:
        raise ValueError("at least one normalized tool report is required")
    reference = runs[0]
    comparison_key = (
        reference["target_id"],
        reference["commit"],
        int(reference["scope_files"]),
        int(reference["scope_loc"]),
    )

    seen_tools = set()
    for run in runs:
        key = (
            run["target_id"],
            run["commit"],
            int(run["scope_files"]),
            int(run["scope_loc"]),
        )
        if key != comparison_key:
            raise ValueError(
                "tool reports are not directly comparable because target/commit/scope "
                "differs"
            )
        tool = str(run["tool"])
        if tool in seen_tools:
            raise ValueError(
                f"duplicate tool result is ambiguous for one comparison: {tool}"
            )
        seen_tools.add(tool)


def compare_normalized_reports(paths: Sequence[Path]) -> MultiToolComparison:
    if len(paths) < 2:
        raise ValueError("at least two normalized tool reports are required")
    runs = [load_normalized_report(path.resolve()) for path in paths]
    validate_comparable_runs(runs)
    reference = runs[0]

    summaries: List[ToolComparisonSummary] = []
    location_sets: Dict[str, Set[Location]] = {}
    locations_by_tool: Dict[str, List[Dict[str, Any]]] = {}
    schema_versions = {str(run["tool"]): int(run["schema_version"]) for run in runs}

    for run in runs:
        tool = str(run["tool"])
        diagnostics = [
            item for item in run["diagnostics"] if isinstance(item, Mapping)
        ]
        locations = _diagnostic_locations(run)
        location_sets[tool] = locations
        locations_by_tool[tool] = _location_rows(run)
        peak = run.get("peak_memory_mb")
        summaries.append(
            ToolComparisonSummary(
                tool=tool,
                tool_version=str(run["tool_version"]),
                schema_version=int(run["schema_version"]),
                run_id=str(run["run_id"]),
                diagnostic_count=len(diagnostics),
                location_count=len(locations),
                elapsed_seconds=float(run["elapsed_seconds"]),
                peak_memory_mb=float(peak) if peak is not None else None,
                evidence_type_counts=_count_field(diagnostics, "evidence_type"),
                severity_counts=_count_field(diagnostics, "severity", "unassessed"),
            )
        )

    overlaps: List[PairwiseOverlap] = []
    for left, right in combinations(sorted(location_sets), 2):
        left_locations = location_sets[left]
        right_locations = location_sets[right]
        overlaps.append(
            PairwiseOverlap(
                left_tool=left,
                right_tool=right,
                exact_location_overlap=len(left_locations & right_locations),
                left_only_locations=len(left_locations - right_locations),
                right_only_locations=len(right_locations - left_locations),
            )
        )

    return MultiToolComparison(
        target_id=str(reference["target_id"]),
        commit=str(reference["commit"]),
        scope_files=int(reference["scope_files"]),
        scope_loc=int(reference["scope_loc"]),
        summaries=sorted(summaries, key=lambda item: item.tool),
        pairwise_overlaps=overlaps,
        locations_by_tool=dict(sorted(locations_by_tool.items())),
        schema_versions=schema_versions,
        limitations=[
            item for item in (
                _cross_version_note(schema_versions),
                "Exact file/line overlap is descriptive and does not equal root-cause overlap.",
                "A diagnostic unique to one tool is not automatically a false positive or false negative.",
                "No Precision/Recall is computed without an adequate labeled ground-truth set.",
                "No runtime triggering, exploitability analysis, or vulnerability voting is performed.",
            ) if item is not None
        ],
    )


def render_markdown(result: MultiToolComparison) -> str:
    lines = [
        "# Multi-tool Static Analysis Comparison",
        "",
        "> Descriptive comparison only. Diagnostics are evidence/candidates, not "
        "validated vulnerabilities.",
        "",
        "## Fixed comparison scope",
        "",
        f"- Target ID: {result.target_id}",
        f"- Commit: {result.commit}",
        f"- Files: {result.scope_files}",
        f"- LOC: {result.scope_loc}",
        f"- Schema versions: {', '.join(f'{tool}=v{v}' for tool, v in sorted(result.schema_versions.items())) or 'unknown'}",
        "",
        "## Tool summary",
        "",
        "| Tool | Version | Schema | Diagnostics | Locations | Seconds | Peak MB | Evidence types |",
        "|---|---|---|---:|---:|---:|---:|---|",
    ]

    for item in result.summaries:
        peak = f"{item.peak_memory_mb:.2f}" if item.peak_memory_mb is not None else "n/a"
        evidence = ", ".join(
            f"{key}:{value}" for key, value in item.evidence_type_counts.items()
        ) or "(none)"
        lines.append(
            f"| {item.tool} | {item.tool_version} | v{item.schema_version} | "
            f"{item.diagnostic_count} | "
            f"{item.location_count} | {item.elapsed_seconds:.6f} | {peak} | "
            f"{evidence} |"
        )

    lines.extend(
        [
            "",
            "## Exact-location overlap",
            "",
            "| Left | Right | Exact overlap | Left only | Right only |",
            "|---|---|---:|---:|---:|",
        ]
    )
    for item in result.pairwise_overlaps:
        lines.append(
            f"| {item.left_tool} | {item.right_tool} | "
            f"{item.exact_location_overlap} | {item.left_only_locations} | "
            f"{item.right_only_locations} |"
        )

    lines.extend(["", "## Interpretation limits", ""])
    for limitation in result.limitations:
        lines.append(f"- {limitation}")
    lines.append("")
    return "\n".join(lines)


def write_reports(
    result: MultiToolComparison,
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
