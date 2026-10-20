"""Descriptive comparison of the text and AST candidate scanners.

Reads two ScanResult JSON reports (one text engine, one ast engine) over the
same target and aligns candidates by file + line + rule_id. It reports overlap
and differences without labeling either side a false/true positive.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


LocationKey = Tuple[str, int, str]


@dataclass(frozen=True)
class CandidateLocation:
    file: str
    line: int
    rule_id: str

    def to_dict(self) -> Dict[str, Any]:
        return {"file": self.file, "line": self.line, "rule_id": self.rule_id}


@dataclass
class ScannerComparison:
    target: str
    text_count: int
    ast_count: int
    overlap_count: int
    text_only: List[CandidateLocation] = field(default_factory=list)
    ast_only: List[CandidateLocation] = field(default_factory=list)
    overlap: List[CandidateLocation] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "text_count": self.text_count,
            "ast_count": self.ast_count,
            "overlap_count": self.overlap_count,
            "text_only_candidates": [item.to_dict() for item in self.text_only],
            "ast_only_candidates": [item.to_dict() for item in self.ast_only],
            "overlap_candidates": [item.to_dict() for item in self.overlap],
            "interpretation": (
                "Descriptive candidate-location comparison only. A text-only candidate is "
                "not automatically a false positive, an ast-only candidate is not "
                "automatically a true positive, and an overlap is not a vulnerability vote. "
                "All differences need manual review."
            ),
        }


def _relative_to_target(target: str, file_path: str) -> str:
    try:
        return Path(file_path).resolve().relative_to(Path(target).resolve()).as_posix()
    except (OSError, ValueError):
        return file_path


def _load_candidates(report_path: Path) -> Tuple[str, Set[LocationKey], List[CandidateLocation]]:
    data = json.loads(report_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"scan report must be a JSON object: {report_path}")
    target = str(data.get("target", ""))
    if not target:
        raise ValueError(f"scan report has no target: {report_path}")

    keys: Set[LocationKey] = set()
    rows: List[CandidateLocation] = []
    for finding in data.get("findings", []):
        if not isinstance(finding, dict):
            continue
        file_path = str(finding.get("file_path", ""))
        line = finding.get("line")
        rule_id = str(finding.get("rule_id", ""))
        if not file_path or line is None:
            continue
        try:
            line_number = int(line)
        except (TypeError, ValueError):
            continue
        if line_number < 1:
            continue
        relative = _relative_to_target(target, file_path)
        keys.add((relative, line_number, rule_id))
        rows.append(CandidateLocation(file=relative, line=line_number, rule_id=rule_id))
    return target, keys, rows


def compare_text_and_ast(
    text_report_path: Path,
    ast_report_path: Path,
) -> ScannerComparison:
    text_target, text_keys, text_rows = _load_candidates(text_report_path)
    ast_target, ast_keys, ast_rows = _load_candidates(ast_report_path)

    if text_target != ast_target:
        raise ValueError(
            f"reports target different roots: {text_target!r} vs {ast_target!r}"
        )

    overlap_keys = text_keys & ast_keys
    text_only_keys = text_keys - ast_keys
    ast_only_keys = ast_keys - text_keys

    def _select(rows: List[CandidateLocation], wanted: Set[LocationKey]) -> List[CandidateLocation]:
        selected: List[CandidateLocation] = []
        for row in rows:
            if (row.file, row.line, row.rule_id) in wanted:
                selected.append(row)
        return sorted(selected, key=lambda r: (r.file, r.line, r.rule_id))

    return ScannerComparison(
        target=text_target,
        text_count=len(text_keys),
        ast_count=len(ast_keys),
        overlap_count=len(overlap_keys),
        text_only=_select(text_rows, text_only_keys),
        ast_only=_select(ast_rows, ast_only_keys),
        overlap=_select(text_rows, overlap_keys),
    )


def render_markdown(result: ScannerComparison) -> str:
    lines = [
        "# Text vs AST Candidate Comparison",
        "",
        "> Descriptive comparison only. Differences are review leads, not "
        "false-positive or true-positive verdicts.",
        "",
        "## Summary",
        "",
        f"- Target: {result.target}",
        f"- Text candidates: {result.text_count}",
        f"- AST candidates: {result.ast_count}",
        f"- Overlap: {result.overlap_count}",
        f"- Text only: {len(result.text_only)}",
        f"- AST only: {len(result.ast_only)}",
        "",
        "## AST-only candidates (review whether text regex missed them)",
        "",
    ]
    if result.ast_only:
        lines.append("| File | Line | Rule |")
        lines.append("|---|---|---|")
        for item in result.ast_only:
            lines.append(f"| {item.file} | {item.line} | {item.rule_id} |")
    else:
        lines.append("(none)")

    lines.extend(["", "## Text-only candidates (review whether AST dropped them)", ""])
    if result.text_only:
        lines.append("| File | Line | Rule |")
        lines.append("|---|---|---|")
        for item in result.text_only:
            lines.append(f"| {item.file} | {item.line} | {item.rule_id} |")
    else:
        lines.append("(none)")

    lines.extend(["", "## Overlap candidates", ""])
    if result.overlap:
        lines.append("| File | Line | Rule |")
        lines.append("|---|---|---|")
        for item in result.overlap:
            lines.append(f"| {item.file} | {item.line} | {item.rule_id} |")
    else:
        lines.append("(none)")

    lines.extend(["", "## Interpretation limits", ""])
    for note in [
        "A text-only candidate may be a comment/string/macro false positive the AST correctly dropped.",
        "An ast-only candidate may be a real call the text regex missed (e.g. spacing/order).",
        "Neither side is a validated vulnerability; all candidates remain unassessed.",
    ]:
        lines.append(f"- {note}")
    lines.append("")
    return "\n".join(lines)


def write_reports(
    result: ScannerComparison,
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
