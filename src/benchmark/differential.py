"""Vulnerable/fixed/safe/unrelated discrimination without TP/FP verdicts."""

from dataclasses import asdict, dataclass
import re
from typing import Dict, Iterable, Mapping, Optional


CASE_KINDS = {"vulnerable", "fixed", "safe", "unrelated"}
OBSERVATION_STATUSES = {
    "possible_hit",
    "no_observed_candidate_shape",
    "unknown_incomplete_analysis",
    "not_applicable",
}
ANALYSIS_COVERAGE = {"complete", "incomplete", "incompatible", "not_run"}
CLASSIFICATIONS = {"vulnerable_only", "both_revisions", "control_hit", "unknown"}
MATCH_BASES = {
    "file_overlap", "symbol_overlap", "patch_region", "guard_relation", "path_evidence",
}


@dataclass(frozen=True)
class RootCauseObservation:
    case_kind: str
    status: str
    analysis_coverage: str
    run_id: Optional[str] = None
    source_report: Optional[str] = None
    source_sha256: Optional[str] = None
    match_basis: Optional[str] = None
    reason: str = ""

    def __post_init__(self) -> None:
        if self.case_kind not in CASE_KINDS:
            raise ValueError("unsupported case_kind")
        if self.status not in OBSERVATION_STATUSES:
            raise ValueError("unsupported observation status")
        if self.analysis_coverage not in ANALYSIS_COVERAGE:
            raise ValueError("unsupported analysis coverage")
        if self.match_basis is not None and self.match_basis not in MATCH_BASES:
            raise ValueError("unsupported match_basis")
        if self.status == "possible_hit":
            if self.analysis_coverage != "complete":
                raise ValueError("possible_hit requires complete analysis coverage")
            if not self.source_sha256 or not re.fullmatch(r"[a-f0-9]{64}", self.source_sha256):
                raise ValueError("possible_hit requires a source SHA-256")
            if self.match_basis is None:
                raise ValueError("possible_hit requires match_basis")
        if self.status == "no_observed_candidate_shape" and self.analysis_coverage != "complete":
            raise ValueError("no_observed_candidate_shape requires complete coverage")
        if self.status == "not_applicable" and (
            self.analysis_coverage != "incompatible" or not self.reason.strip()
        ):
            raise ValueError("not_applicable requires incompatible coverage and reason")
        if not isinstance(self.reason, str):
            raise ValueError("reason must be a string")


@dataclass(frozen=True)
class PatchDiscrimination:
    sample_id: str
    root_instance_id: str
    root_cause_group: str
    observations: Mapping[str, RootCauseObservation]
    classification: str
    reason: str

    def __post_init__(self) -> None:
        for name in ("sample_id", "root_instance_id", "root_cause_group"):
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", getattr(self, name)):
                raise ValueError(f"{name} must be a safe identifier")
        if set(self.observations) != CASE_KINDS:
            raise ValueError("patch discrimination requires all four case kinds")
        if self.classification not in CLASSIFICATIONS:
            raise ValueError("unsupported discrimination classification")
        if not self.reason.strip():
            raise ValueError("discrimination reason must not be empty")

    def to_dict(self) -> Dict[str, object]:
        return {
            "schema_version": 1,
            "sample_id": self.sample_id,
            "root_instance_id": self.root_instance_id,
            "root_cause_group": self.root_cause_group,
            "classification": self.classification,
            "reason": self.reason,
            "observations": {
                key: asdict(value) for key, value in sorted(self.observations.items())
            },
            "interpretation": (
                "Patch discrimination is descriptive evidence, not TP/FP/FN or a "
                "vulnerability verdict."
            ),
        }


def build_patch_discrimination(
    *,
    sample_id: str,
    root_instance_id: str,
    root_cause_group: str,
    observations: Iterable[RootCauseObservation],
) -> PatchDiscrimination:
    items = tuple(observations)
    by_kind = {item.case_kind: item for item in items}
    if len(items) != 4 or len(by_kind) != 4:
        raise ValueError("exactly one observation is required for each case kind")

    if any(
        item.status in {"unknown_incomplete_analysis", "not_applicable"}
        for item in items
    ):
        classification = "unknown"
        reason = "At least one required analysis is incomplete or inapplicable."
    elif any(
        item.case_kind in {"safe", "unrelated"} and item.status == "possible_hit"
        for item in items
    ):
        classification = "control_hit"
        reason = "A safe or unrelated control produced the candidate shape."
    elif (
        by_kind["vulnerable"].status == "possible_hit"
        and by_kind["fixed"].status == "possible_hit"
    ):
        classification = "both_revisions"
        reason = "The candidate shape remains present in vulnerable and fixed revisions."
    elif (
        by_kind["vulnerable"].status == "possible_hit"
        and all(
            by_kind[kind].status == "no_observed_candidate_shape"
            for kind in ("fixed", "safe", "unrelated")
        )
    ):
        classification = "vulnerable_only"
        reason = "The candidate shape was observed only in the vulnerable revision."
    else:
        classification = "unknown"
        reason = (
            "The observations do not support the requested discrimination classes; "
            "raw observations are preserved."
        )
    return PatchDiscrimination(
        sample_id=sample_id,
        root_instance_id=root_instance_id,
        root_cause_group=root_cause_group,
        observations=by_kind,
        classification=classification,
        reason=reason,
    )


def render_patch_discrimination_markdown(result: PatchDiscrimination) -> str:
    lines = [
        "# Patch Discrimination",
        "",
        "> Descriptive root-cause discrimination only; not TP/FP/FN and not a vulnerability verdict.",
        "",
        f"- Sample: `{result.sample_id}`",
        f"- Root instance: `{result.root_instance_id}`",
        f"- Root cause: `{result.root_cause_group}`",
        f"- Classification: `{result.classification}`",
        f"- Reason: {result.reason}",
        "",
        "| case | status | coverage | match_basis | run_id |",
        "|---|---|---|---|---|",
    ]
    for kind in ("vulnerable", "fixed", "safe", "unrelated"):
        item = result.observations[kind]
        lines.append(
            f"| {kind} | {item.status} | {item.analysis_coverage} | "
            f"{item.match_basis or '-'} | {item.run_id or '-'} |"
        )
    return "\n".join(lines) + "\n"
