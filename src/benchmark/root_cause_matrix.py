"""Root-cause level hit matrix across historical samples and tools.

Classifies, per sample, whether each tool's candidates touch the sample's
affected file + symbol region. States are possible_hit / miss / unknown /
not_applicable only; never TP/FP/FN and never a vulnerability vote. This is the
missing link between "how many warnings" (tool_matrix) and "did it touch the
real root cause" (this matrix).
"""

from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

from src.benchmark.historical import HistoricalSample


ALLOWED_STATUSES = {"possible_hit", "miss", "unknown", "not_applicable"}


@dataclass(frozen=True)
class ToolCandidate:
    """One candidate location a tool produced (file + optional symbol/line)."""

    file: str
    symbol: Optional[str] = None
    line: Optional[int] = None


@dataclass(frozen=True)
class RootCauseHit:
    sample_id: str
    root_cause_group: str
    tool: str
    status: str
    evidence_count: int


@dataclass
class RootCauseMatrix:
    rows: List[RootCauseHit] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "rows": [asdict(row) for row in self.rows],
            "interpretation": (
                "Root-cause hit matrix only. possible_hit means a tool touched the "
                "affected file/symbol region; it is not a true positive, and miss is "
                "not a false negative. unknown means the tool was not run on that "
                "sample; not_applicable means the tool does not apply to the sample "
                "weakness type. No Precision/Recall is computed."
            ),
        }


def _hit_affected(sample: HistoricalSample, candidate: ToolCandidate) -> bool:
    if candidate.file not in sample.affected_files:
        return False
    if not sample.affected_symbols:
        return True
    if candidate.symbol is None:
        return False
    return candidate.symbol in sample.affected_symbols


def classify_tool_hit(
    sample: HistoricalSample,
    tool: str,
    candidates: Optional[List[ToolCandidate]],
) -> RootCauseHit:
    """Classify one tool against one sample.

    ``candidates is None`` means the tool was not run -> unknown.
    """
    if candidates is None:
        status = "unknown"
        count = 0
    else:
        hits = [c for c in candidates if _hit_affected(sample, c)]
        status = "possible_hit" if hits else "miss"
        count = len(hits)
    return RootCauseHit(
        sample_id=sample.sample_id,
        root_cause_group=sample.root_cause_group,
        tool=tool,
        status=status,
        evidence_count=count,
    )


def build_root_cause_hit_matrix(
    samples: List[HistoricalSample],
    tool_candidates: Dict[str, Optional[List[ToolCandidate]]],
) -> RootCauseMatrix:
    """Build a sample x tool hit matrix.

    ``tool_candidates`` maps tool name to its candidates, or None when the tool
    was not run (which yields ``unknown`` for every sample).
    """
    tools = sorted(tool_candidates.keys())
    rows: List[RootCauseHit] = []
    for sample in samples:
        for tool in tools:
            rows.append(classify_tool_hit(sample, tool, tool_candidates.get(tool)))
    return RootCauseMatrix(rows=rows)


def render_markdown(result: RootCauseMatrix) -> str:
    samples = sorted({row.sample_id for row in result.rows})
    tools = sorted({row.tool for row in result.rows})
    lines = [
        "# Root-Cause Hit Matrix",
        "",
        "> possible_hit = tool touched the affected file/symbol region (not a TP); "
        "miss = tool ran but did not touch it (not a FN); unknown = tool not run.",
        "",
        "| sample | " + " | ".join(tools) + " |",
        "|---|" + "---|" * len(tools),
    ]
    by_sample = {sample_id: {row.tool: row for row in result.rows if row.sample_id == sample_id} for sample_id in samples}
    for sample_id in samples:
        cells = []
        for tool in tools:
            row = by_sample[sample_id].get(tool)
            if row is None:
                cells.append("unknown")
            elif row.status == "possible_hit":
                cells.append(f"possible_hit({row.evidence_count})")
            else:
                cells.append(row.status)
        lines.append(f"| {sample_id} | " + " | ".join(cells) + " |")
    lines.extend(["", "## Interpretation limits", ""])
    for note in [
        "No TP/FP/FN is assigned.",
        "No Precision/Recall is computed from 3 samples.",
        "possible_hit is only region overlap, not a vulnerability vote.",
        "unknown means the tool has not actually been run on that sample yet.",
    ]:
        lines.append(f"- {note}")
    lines.append("")
    return "\n".join(lines)
