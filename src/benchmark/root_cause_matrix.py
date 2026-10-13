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
ALLOWED_MATCH_BASES = {
    "file_overlap", "symbol_overlap", "patch_region", "guard_relation", "path_evidence",
}
_MATCH_BASIS_RANK = {
    "file_overlap": 1,
    "symbol_overlap": 2,
    "patch_region": 3,
    "guard_relation": 4,
    "path_evidence": 5,
}


class _NotApplicable:
    """Marker for a tool that cannot analyse this analysis unit at all.

    ``unknown`` means "the tool has not been run"; ``not_applicable`` means "the
    tool was run and cannot apply here" — for example a build-dependent analyser
    handed a single file whose headers are absent from the scanned tree, which
    fails to form a translation unit instead of reporting a finding.
    """

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "NOT_APPLICABLE"


NOT_APPLICABLE = _NotApplicable()


@dataclass(frozen=True)
class ToolCandidate:
    """One candidate location a tool produced (file + optional symbol/line)."""

    file: str
    symbol: Optional[str] = None
    line: Optional[int] = None
    match_basis: Optional[str] = None

    def __post_init__(self) -> None:
        if self.match_basis is not None and self.match_basis not in ALLOWED_MATCH_BASES:
            raise ValueError(f"unsupported match_basis: {self.match_basis}")


@dataclass(frozen=True)
class RootCauseHit:
    sample_id: str
    root_cause_group: str
    weakness: str
    tool: str
    status: str
    evidence_count: int
    match_basis: Optional[str] = None
    revision: str = "vulnerable"
    commit: Optional[str] = None
    run_id: Optional[str] = None
    source_report: Optional[str] = None
    source_sha256: Optional[str] = None
    reason: str = ""
    tool_version: Optional[str] = None
    scope_files: Optional[int] = None
    scope_loc: Optional[int] = None
    analyzed_files: tuple = ()
    run_status: Optional[str] = None
    limitations: tuple = ()
    source_snapshots: tuple = ()


@dataclass(frozen=True)
class SampleToolRun:
    """Saved evidence bound to one sample, tool and exact revision."""

    sample_id: str
    revision: str
    tool: str
    commit: str
    candidates: object
    run_id: str
    source_report: str
    source_sha256: str
    reason: str = ""
    tool_version: str = "unknown"
    scope_files: Optional[int] = None
    scope_loc: Optional[int] = None
    analyzed_files: tuple = ()
    run_status: str = "completed"
    limitations: tuple = ()
    source_snapshots: tuple = ()


@dataclass
class RootCauseMatrix:
    rows: List[RootCauseHit] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "rows": [asdict(row) for row in self.rows],
            "interpretation": (
                "Root-cause hit matrix only. possible_hit means a tool touched the "
                "affected file/symbol region; it is not a true positive, and miss is "
                "not a false negative. unknown means missing/failed analysis, incomplete "
                "scope or unresolved symbol identity; not_applicable means the tool "
                "was run but cannot apply to "
                "this analysis unit or weakness type (e.g. a build-dependent analyser "
                "handed a single file whose headers are absent). No Precision/Recall "
                "is computed."
            ),
        }


def _candidate_match_basis(
    sample: HistoricalSample,
    candidate: ToolCandidate,
) -> Optional[str]:
    if candidate.file not in sample.affected_files:
        return None
    if not sample.affected_symbols:
        return candidate.match_basis or "file_overlap"
    if candidate.symbol is None:
        return None
    if candidate.symbol not in sample.affected_symbols:
        return None
    return candidate.match_basis or "symbol_overlap"


def classify_tool_hit(
    sample: HistoricalSample,
    tool: str,
    candidates: object,
) -> RootCauseHit:
    """Classify one tool against one sample.

    ``candidates is None`` means the tool was not run -> unknown.
    ``candidates is NOT_APPLICABLE`` means the tool cannot analyse this unit
    (e.g. a build-dependent analyser on an unbuildable single file) ->
    not_applicable. Anything else must be a list of ToolCandidate.
    """
    hits = []
    if candidates is NOT_APPLICABLE:
        status = "not_applicable"
        count = 0
    elif candidates is None:
        status = "unknown"
        count = 0
    else:
        if not isinstance(candidates, (list, tuple)):
            raise ValueError(
                "tool candidates must be a list, None (not run) or NOT_APPLICABLE"
            )
        for candidate in candidates:
            basis = _candidate_match_basis(sample, candidate)
            if basis is not None:
                hits.append((candidate, basis))
        unresolved = any(
            c.file in sample.affected_files and sample.affected_symbols
            and c.symbol is None for c in candidates
        )
        status = "possible_hit" if hits else "unknown" if unresolved else "miss"
        count = len(hits)
    match_basis = None
    if count:
        match_basis = max(
            (basis for _, basis in hits),
            key=lambda value: _MATCH_BASIS_RANK[value],
        )
    return RootCauseHit(
        sample_id=sample.sample_id,
        root_cause_group=sample.root_cause_group,
        weakness=sample.weakness,
        tool=tool,
        status=status,
        evidence_count=count,
        match_basis=match_basis,
    )


def build_revision_hit_matrix(
    samples: List[HistoricalSample],
    runs: List[SampleToolRun],
    tools: Optional[List[str]] = None,
) -> RootCauseMatrix:
    """Isolate samples and revisions; missing or failed runs remain unknown."""
    by_sample = {sample.sample_id: sample for sample in samples}
    if len(by_sample) != len(samples):
        raise ValueError("duplicate historical sample_id")
    indexed = {}
    for run in runs:
        if run.sample_id not in by_sample:
            raise ValueError(f"unknown sample_id: {run.sample_id}")
        if run.revision not in {"vulnerable", "fixed"}:
            raise ValueError(f"unsupported revision: {run.revision}")
        sample = by_sample[run.sample_id]
        expected = getattr(sample, f"{run.revision}_commit")
        if run.commit != expected:
            raise ValueError(f"commit mismatch for {run.sample_id}/{run.revision}")
        key = (run.sample_id, run.revision, run.tool)
        if key in indexed:
            raise ValueError(f"duplicate benchmark run: {key}")
        indexed[key] = run
    tool_names = sorted(set(tools or []) | {run.tool for run in runs})
    rows = []
    for sample in samples:
        for revision in ("vulnerable", "fixed"):
            for tool in tool_names:
                run = indexed.get((sample.sample_id, revision, tool))
                hit = classify_tool_hit(sample, tool, run.candidates if run else None)
                reason = run.reason if run else "No saved run supplied for this revision."
                if run and hit.status == "unknown" and not reason:
                    reason = "Candidate symbol is unresolved; region overlap is unknown."
                rows.append(RootCauseHit(
                    sample_id=hit.sample_id, root_cause_group=hit.root_cause_group,
                    weakness=hit.weakness, tool=tool, status=hit.status,
                    evidence_count=hit.evidence_count, revision=revision,
                    commit=getattr(sample, f"{revision}_commit"),
                    run_id=run.run_id if run else None,
                    source_report=run.source_report if run else None,
                    source_sha256=run.source_sha256 if run else None, reason=reason,
                    tool_version=run.tool_version if run else None,
                    scope_files=run.scope_files if run else None,
                    scope_loc=run.scope_loc if run else None,
                    analyzed_files=run.analyzed_files if run else (),
                    run_status=run.run_status if run else None,
                    limitations=run.limitations if run else (),
                    source_snapshots=run.source_snapshots if run else (),
                ))
    return RootCauseMatrix(rows=rows)


def build_root_cause_hit_matrix(
    samples: List[HistoricalSample],
    tool_candidates: Dict[str, object],
) -> RootCauseMatrix:
    """Build a sample x tool hit matrix.

    ``tool_candidates`` maps tool name to either its candidate list, ``None``
    when the tool was not run (``unknown``), or ``NOT_APPLICABLE`` when the tool
    was run but cannot apply to this analysis unit (``not_applicable``).
    """
    tools = sorted(tool_candidates.keys())
    rows: List[RootCauseHit] = []
    for sample in samples:
        for tool in tools:
            rows.append(classify_tool_hit(sample, tool, tool_candidates.get(tool)))
    return RootCauseMatrix(rows=rows)


def render_markdown(result: RootCauseMatrix) -> str:
    sample_revisions = sorted({(row.sample_id, row.revision) for row in result.rows})
    tools = sorted({row.tool for row in result.rows})
    lines = [
        "# Root-Cause Hit Matrix",
        "",
        "> possible_hit = tool touched the affected file/symbol region (not a TP); "
        "miss = completed analysis with no region overlap (not a FN); "
        "unknown = missing/failed run or unresolved location; "
        "not_applicable = evidenced incompatible analysis unit.",
        "",
        "| sample_id | revision | root_cause_group | weakness | " + " | ".join(tools) + " |",
        "|---|---|---|---|" + "---|" * len(tools),
    ]
    for sample_id, revision in sample_revisions:
        meta = {row.tool: row for row in result.rows
                if row.sample_id == sample_id and row.revision == revision}
        first = next(iter(meta.values()))
        group = first.root_cause_group
        weakness = first.weakness
        cells = []
        for tool in tools:
            row = meta.get(tool)
            if row is None:
                cells.append("unknown")
            elif row.status == "possible_hit":
                cells.append(f"possible_hit({row.evidence_count})")
            else:
                cells.append(row.status)
        lines.append(f"| {sample_id} | {revision} | {group} | {weakness} | " + " | ".join(cells) + " |")
    lines.extend(["", "## Interpretation limits", ""])
    for note in [
        "No TP/FP/FN is assigned.",
        "No Precision/Recall is computed from this limited corpus.",
        "possible_hit is only region overlap, not a vulnerability vote.",
        "Unknown also includes failed runs and candidates lacking symbol identity.",
    ]:
        lines.append(f"- {note}")
    lines.append("")
    return "\n".join(lines)
