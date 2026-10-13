"""Revision-oriented analysis records for teammate A static scanning.

This module describes how deterministic detector results are reused by
snapshot, revision-range and cross-version audits. It does not fetch source,
schedule jobs, invoke external scanners or promote findings to vulnerabilities.
"""

from dataclasses import asdict, dataclass
import re
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

from .contracts import DetectorRun, ScanRequest, safe_relative_path


ANALYSIS_MODES = {"snapshot", "revision_range", "cross_version"}
REVISION_ROLES = {
    "baseline", "endpoint", "target", "control_vulnerable", "control_fixed",
    "control_safe", "control_unrelated",
}
ANALYSIS_UNITS = {
    "translation_unit", "file", "component_slice", "header_only", "unknown",
}
INCLUDE_STATUSES = {
    "complete", "partial", "failed", "not_run", "not_applicable",
}


def _optional_sha256(value: Optional[str], field_name: str) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 or null")
    return value


def _safe_paths(values: Iterable[str]) -> Tuple[str, ...]:
    result = tuple(values)
    if len(result) != len(set(result)):
        raise ValueError("analysis paths must be unique")
    for path in result:
        safe_relative_path(path)
    return result


@dataclass(frozen=True)
class AnalysisRunContext:
    """Sidecar facts that make analysis coverage comparable across revisions."""

    analysis_mode: str
    revision_role: str
    analysis_unit: str
    build_profile: str
    include_status: str
    analyzed_files: Tuple[str, ...] = ()
    compile_commands_sha256: Optional[str] = None
    macro_profile_sha256: Optional[str] = None
    detector_query_sha256: Optional[str] = None
    source_snapshot_sha256: Optional[str] = None
    limitations: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.analysis_mode not in ANALYSIS_MODES:
            raise ValueError("unsupported analysis_mode")
        if self.revision_role not in REVISION_ROLES:
            raise ValueError("unsupported revision_role")
        if self.analysis_unit not in ANALYSIS_UNITS:
            raise ValueError("unsupported analysis_unit")
        if self.include_status not in INCLUDE_STATUSES:
            raise ValueError("unsupported include_status")
        if not isinstance(self.build_profile, str) or not self.build_profile.strip():
            raise ValueError("build_profile must not be empty")
        object.__setattr__(self, "analyzed_files", _safe_paths(self.analyzed_files))
        for name in (
            "compile_commands_sha256", "macro_profile_sha256",
            "detector_query_sha256", "source_snapshot_sha256",
        ):
            object.__setattr__(self, name, _optional_sha256(getattr(self, name), name))
        limitations = tuple(self.limitations)
        if not all(isinstance(item, str) and item.strip() for item in limitations):
            raise ValueError("limitations must be non-empty strings")
        object.__setattr__(self, "limitations", limitations)
        if self.include_status == "not_applicable" and not limitations:
            raise ValueError("not_applicable analysis requires an explicit limitation")

    @property
    def coverage_complete(self) -> bool:
        return self.include_status == "complete"

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["analyzed_files"] = list(self.analyzed_files)
        data["limitations"] = list(self.limitations)
        data["coverage_complete"] = self.coverage_complete
        return data


@dataclass(frozen=True)
class RevisionAnalysis:
    """One pinned revision and deterministic detector runs performed on it."""

    request: ScanRequest
    revision_role: str
    run_contexts: Mapping[str, AnalysisRunContext]
    detector_runs: Tuple[DetectorRun, ...]
    limitations: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.revision_role not in REVISION_ROLES:
            raise ValueError("unsupported revision_role")
        run_ids = [run.detector_id for run in self.detector_runs]
        if len(run_ids) != len(set(run_ids)):
            raise ValueError("duplicate detector run")
        if set(run_ids) != set(self.run_contexts):
            raise ValueError("run_contexts must bind exactly one context per detector")
        for detector_id, context in self.run_contexts.items():
            if not detector_id.strip():
                raise ValueError("detector_id must not be empty")
            if context.revision_role != self.revision_role:
                raise ValueError("run context revision role mismatch")
        limitations = tuple(self.limitations)
        if not all(isinstance(item, str) and item.strip() for item in limitations):
            raise ValueError("limitations must be non-empty strings")
        object.__setattr__(self, "limitations", limitations)

    @property
    def commit(self) -> str:
        return self.request.commit

    @property
    def repository(self) -> str:
        return self.request.repository

    @property
    def all_coverage_complete(self) -> bool:
        return all(context.coverage_complete for context in self.run_contexts.values())

    def findings_by_rule(self) -> Dict[str, Tuple[str, ...]]:
        return {
            run.detector_id: tuple(
                f"{finding.file}:{finding.line}:{finding.rule_id}"
                for finding in run.findings
            )
            for run in self.detector_runs
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "repository": self.repository,
            "commit": self.commit,
            "revision_role": self.revision_role,
            "request": asdict(self.request),
            "run_contexts": {
                key: value.to_dict() for key, value in sorted(self.run_contexts.items())
            },
            "detector_runs": [asdict(run) for run in self.detector_runs],
            "limitations": list(self.limitations),
            "interpretation": (
                "Deterministic static-analysis record only. Empty findings are not "
                "proof of safety and incomplete analysis remains unknown."
            ),
        }


def compare_revision_analyses(
    baseline: RevisionAnalysis,
    endpoint: RevisionAnalysis,
    *,
    comparison_identity: str,
) -> Dict[str, Any]:
    """Compare stable finding identities without claiming when a bug was introduced."""

    if baseline.repository != endpoint.repository:
        raise ValueError("revision comparison requires the same repository")
    if baseline.commit == endpoint.commit:
        raise ValueError("revision comparison requires distinct commits")
    if baseline.revision_role != "baseline" or endpoint.revision_role != "endpoint":
        raise ValueError("revision comparison requires baseline and endpoint roles")
    if not comparison_identity.strip():
        raise ValueError("comparison_identity must not be empty")

    baseline_findings = baseline.findings_by_rule()
    endpoint_findings = endpoint.findings_by_rule()
    rows = []
    for detector_id in sorted(set(baseline_findings) | set(endpoint_findings)):
        if detector_id not in baseline_findings or detector_id not in endpoint_findings:
            rows.append({
                "detector_id": detector_id,
                "finding_identity": None,
                "state": "unknown",
                "reason": "Detector did not run on both revisions.",
            })
        elif not baseline.all_coverage_complete or not endpoint.all_coverage_complete:
            rows.append({
                "detector_id": detector_id,
                "finding_identity": None,
                "state": "unknown",
                "reason": "Detector coverage is incomplete on at least one revision.",
            })
        else:
            old = set(baseline_findings[detector_id])
            new = set(endpoint_findings[detector_id])
            for state, identities in (
                ("new", new - old), ("persistent", new & old), ("disappeared", old - new),
            ):
                rows.extend({
                    "detector_id": detector_id,
                    "finding_identity": identity,
                    "state": state,
                } for identity in sorted(identities))
    return {
        "schema_version": 1,
        "comparison_identity": comparison_identity,
        "repository": baseline.repository,
        "baseline_commit": baseline.commit,
        "endpoint_commit": endpoint.commit,
        "rows": rows,
        "interpretation": (
            "Revision comparison describes candidate persistence only. It does not "
            "prove that a vulnerability was introduced or fixed in the selected range."
        ),
    }


def assess_version_analyses(
    analyses: Iterable[RevisionAnalysis],
    *,
    root_instance_id: str,
) -> Dict[str, Any]:
    """Describe static observations for one root instance across pinned revisions."""

    items = tuple(analyses)
    if not items:
        raise ValueError("at least one revision analysis is required")
    if not root_instance_id.strip():
        raise ValueError("root_instance_id must not be empty")
    repository = items[0].repository
    commits = []
    rows = []
    for analysis in items:
        if analysis.repository != repository:
            raise ValueError("version assessment requires the same repository")
        if analysis.commit in commits:
            raise ValueError("duplicate revision in version assessment")
        commits.append(analysis.commit)
        has_candidate = any(
            finding.rule_id == root_instance_id or finding.symbol == root_instance_id
            for run in analysis.detector_runs
            for finding in run.findings
        )
        if not analysis.all_coverage_complete:
            status = "unknown"
        elif has_candidate:
            status = "possibly_affected"
        else:
            status = "not_present"
        rows.append({
            "commit": analysis.commit,
            "revision_role": analysis.revision_role,
            "status": status,
            "coverage_complete": analysis.all_coverage_complete,
        })
    return {
        "schema_version": 1,
        "repository": repository,
        "root_instance_id": root_instance_id,
        "rows": rows,
        "interpretation": (
            "Static version observations only. possibly_affected is not confirmed "
            "product impact; affected/fixed require independent patch and runtime evidence."
        ),
    }
