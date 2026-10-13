"""Execute FIRST-PARTY detectors; preserve honest per-file coverage and evidence.

Compatibility:
  run_all(context, registry) -> list[ToolRunResult] remains unchanged.
  run_all_with_coverage(...) -> (same results, structured sidecar).
Neither function decides whether a diagnostic represents a real vulnerability.
"""

from hashlib import sha256
from time import perf_counter

from src.benchmark.tool_result import ToolDiagnostic, ToolRunResult
from .contracts import ScanContext, DetectorRun


class DetectorRegistry:
    def __init__(self):
        self._detectors = {}

    def register(self, detector):
        ident = getattr(detector, "detector_id", None)
        if not isinstance(ident, str) or not ident.startswith("ohscanner.") or ident in self._detectors:
            raise ValueError("detector ID must be unique and namespaced")
        if not isinstance(detector.version, str) or not detector.version:
            raise ValueError("detector version required")
        if not isinstance(detector.supported_languages, tuple) or not detector.supported_languages:
            raise ValueError("supported languages required")
        if not isinstance(detector.required_facts, tuple):
            raise ValueError("required_facts must be a tuple")
        # Default AST consumers support independent source-file analysis.
        # Whole-program algorithms must opt into explicit full-scope gating.
        if getattr(detector, "ast_scope", "per_file") not in ("per_file", "whole_scope"):
            raise ValueError("ast_scope must be per_file or whole_scope")
        self._detectors[ident] = detector

    def detectors(self):
        return [self._detectors[key] for key in sorted(self._detectors)]


def _diagnostic_id(detector_id, finding, source_sha256):
    """Stable identity of one finding, bound to the exact source revision.

    The source hash is part of the input on purpose: two runs over the same path
    and line but a different revision must not produce the same ID (contract v2).
    """
    digest = sha256(("|".join((source_sha256, finding.file, str(finding.line),
                               finding.rule_id, finding.message))).encode("utf-8")).hexdigest()[:16]
    return f"{detector_id}:{digest}"


def _bind_source(finding, unit):
    """Resolve a finding's source binding against the unit it was reported in.

    An unset hash is filled from the unit. A *disagreeing* hash is refused rather
    than corrected: the runner has no standing to decide which of the two is the
    real text, and silently preferring either would manufacture the binding this
    field exists to prove.
    """
    if not finding.source_sha256:
        return unit.sha256
    if finding.source_sha256 != unit.sha256:
        raise ValueError("finding source hash does not match the analyzed source")
    return unit.sha256


def _source_bindings(run, selected):
    """Map a run's findings to the source hash each one is actually bound to."""
    paths = {unit.path: unit for unit in selected}
    return {finding: _bind_source(finding, paths[finding.file])
            for finding in run.findings if finding.file in paths}


def _normalized(context, detector, selected, run, elapsed, error=None,
                applicable=None, skipped=None):
    """Normalize one run without hiding any unsupported or skipped file."""
    applicable = tuple(selected) if applicable is None else tuple(applicable)
    skipped = {} if skipped is None else dict(skipped)
    if error is not None:
        run = DetectorRun(detector.detector_id, detector.version, "failed",
                          limitations=(f"Detector failed: {error.__class__.__name__}",))
    if not isinstance(run, DetectorRun):
        raise ValueError("detector must return DetectorRun")
    if run.detector_id != detector.detector_id or run.version != detector.version:
        raise ValueError("detector identity mismatch")
    paths = {unit.path: unit for unit in selected}
    if not set(run.analyzed_files).issubset(paths):
        raise ValueError("reported scope includes unprovided files")
    per_file = dict(run.file_outcomes)
    if not set(per_file).issubset(paths):
        raise ValueError("per-file outcome outside supplied scope")
    if per_file and set(per_file) != set(paths):
        raise ValueError("per-file outcomes must account for every selected source unit")
    if not per_file and run.status == "completed" and set(run.analyzed_files) != set(paths):
        raise ValueError("completed detector skipped a selected source unit")
    if any(state == "complete" and paths[path].parse_status != "complete"
           for path, state in per_file.items()):
        raise ValueError("incomplete source parse cannot claim complete analysis")
    inspected = {path for path, state in per_file.items() if state in ("complete", "partial")}
    if not inspected.issubset(run.analyzed_files):
        raise ValueError("per-file completed/partial units must be in analyzed_files")
    if per_file and not set(run.analyzed_files).issubset(inspected):
        raise ValueError("unverified per-file outcome marked as analyzed")


    findings = []
    seen_ids = set()
    for finding in run.findings:
        if finding.file not in run.analyzed_files:
            raise ValueError("finding outside analyzed scope")
        unit = paths[finding.file]
        if finding.line > len(unit.text.splitlines()):
            raise ValueError("finding location outside source")
        source_sha256 = _bind_source(finding, unit)
        diagnostic_id = _diagnostic_id(detector.detector_id, finding, source_sha256)
        if diagnostic_id in seen_ids:
            raise ValueError("duplicate finding identity")
        seen_ids.add(diagnostic_id)
        findings.append(ToolDiagnostic(
            diagnostic_id=diagnostic_id, provider=detector.detector_id,
            evidence_type=finding.evidence_type, file=finding.file, line=finding.line,
            column=finding.column, rule_id=finding.rule_id, severity="unassessed",
            message=finding.message, candidate_cwe=finding.candidate_cwe,
            confidence="unassessed", symbol=finding.symbol,
            source_sha256=source_sha256,
            consequence_impact=finding.consequence_impact,
            consequence_cwe=finding.consequence_cwe))
    findings.sort(key=lambda item: (item.file, item.line or 0, item.rule_id or "", item.diagnostic_id))
    limitations = list(run.limitations)
    provenance_limitation = (
        "M0 synthetic fixture only; no real Git provenance verified."
        if context.request.provenance == "fixture" else
        "M1 local Git objects pinned by full commit/tree; repository ownership is user-declared."
    )
    limitations.extend((provenance_limitation,
                        "Execution is synchronous; hard timeout/memory isolation is not yet implemented.",
                        "Diagnostic does not establish vulnerability, reachability or security impact."))
    if skipped:
        limitations.append(
            f"INCOMPLETE COVERAGE: {len(skipped)} applicable files not analyzed; "
            "inspect parsing.analysis_status and the coverage sidecar."
        )
    if per_file and any(s != "complete" for s in per_file.values()):
        limitations.append("INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.")
    if run.status == "blocked":
        limitations.append("Coverage incomplete or unsupported; do not infer safety.")
    if run.status == "failed":
        limitations.append("Detector failed; unexamined scope is unknown.")

    # A legacy blocked run's analyzed_files proves inspection, not completeness.
    # Explicit outcomes distinguish complete analysis from partial inspection.
    completed = (
        {path for path, state in per_file.items() if state == "complete"}
        if per_file else set(run.analyzed_files) if run.status == "completed" else set()
    )
    partly_inspected = (
        {path for path, state in per_file.items() if state == "partial"}
        if per_file else set(run.analyzed_files) - completed
    )
    # Even legacy successful detectors cannot upgrade an incomplete source parse.
    source_incomplete = {p for p in completed if paths[p].parse_status != "complete"}
    completed -= source_incomplete
    partly_inspected |= source_incomplete
    if partly_inspected and not any("INCOMPLETE COVERAGE" in value for value in limitations):
        limitations.append("INCOMPLETE COVERAGE: inspected source includes partial/unknown analysis; no safety inference.")
    def analysis_state(path):
        if path in skipped:
            return "not_analyzed"
        if path in completed:
            return "analyzed"
        if path in partly_inspected:
            return "partial"
        return "not_analyzed"

    parsing = [
        {
            "file": unit.path,
            "status": unit.parse_status,
            "issues": list(unit.parse_issues),
            "analysis_status": analysis_state(unit.path),
            "analysis_reason": (
                "" if analysis_state(unit.path) == "analyzed" else
                "detector_model_incomplete" if analysis_state(unit.path) == "partial" else
                skipped.get(unit.path, per_file.get(unit.path, run.status if run.status != "completed" else "not_examined"))
            ),
        }
        for unit in applicable
    ]
    return ToolRunResult(
        # v2: every diagnostic below carries the source hash it was reported against.
        schema_version=2, run_id=context.request.request_id + ":" + detector.detector_id,
        tool=detector.detector_id, tool_version=detector.version,
        target_id=context.request.target_id, commit=context.request.commit,
        scope_files=len(completed | partly_inspected),
        scope_loc=sum(len(paths[p].text.splitlines()) for p in completed | partly_inspected),
        status=run.status, elapsed_seconds=elapsed, diagnostics=findings,
        limitations=limitations, parsing=parsing,
    )


def run_all_with_coverage(context: ScanContext, registry: DetectorRegistry):
    """Return normalized reports plus per-detector coverage and obligations.

    Emits contract v2 (see docs/contracts/ohscanner_detector_contract_v2.md):
    every diagnostic is bound to the source revision it was reported against.
    In particular, 'completed' describes successful work on ELIGIBLE files, not
    whole-component safety. A file in partial AST is not counted as a miss, even
    if other files ran.
    """
    from .fixture import snapshot_digest

    if snapshot_digest(context.units) != context.request.snapshot_sha256:
        raise ValueError("source unit manifest does not match ScanRequest")
    reports, sidecar = [], {"schema_version": 1, "detectors": {}}
    for detector in registry.detectors():
        applicable = tuple(unit for unit in context.units
                           if unit.language in detector.supported_languages)
        selected = applicable
        skipped = {}
        run = None
        error = None
        start = perf_counter()
        if not applicable:
            run = DetectorRun(detector.detector_id, detector.version, "blocked",
                              limitations=("not_applicable: no source with supported language.",))
        else:
            missing = set(detector.required_facts) - set(context.shared_facts)
            if missing:
                skipped = {unit.path: "missing_shared_facts" for unit in applicable}
                run = DetectorRun(
                    detector.detector_id, detector.version, "blocked",
                    limitations=("Missing required shared facts: "
                                 + ", ".join(sorted(missing)),),
                )
                selected = ()
            elif "ast" in detector.required_facts:
                incomplete = tuple(unit for unit in applicable
                                   if unit.parse_status != "complete")
                if getattr(detector, "ast_scope", "per_file") == "whole_scope":
                    if incomplete:
                        selected = ()
                        skipped = {unit.path: "whole_scope_requires_complete_ast"
                                   for unit in applicable}
                        run = DetectorRun(
                            detector.detector_id, detector.version, "blocked",
                            limitations=(f"Whole-scope AST requires every applicable file "
                                         f"to be complete; {len(incomplete)} are incomplete.",),
                        )
                else:
                    selected = tuple(unit for unit in applicable if unit.parse_status == "complete")
                    skipped = {unit.path: "incomplete_ast:" + unit.parse_status
                               for unit in incomplete}
                    if not selected:
                        run = DetectorRun(
                            detector.detector_id, detector.version, "blocked",
                            limitations=("No file has complete AST for this detector.",),
                        )
        if run is None:
            try:
                run = detector.detect(context, selected)
                report = _normalized(context, detector, selected, run,
                                     perf_counter() - start, applicable=applicable,
                                     skipped=skipped)
            except Exception as exc:
                error = exc
                run = None
                report = _normalized(context, detector, selected, run,
                                     perf_counter() - start, error=error,
                                     applicable=applicable, skipped=skipped)
        else:
            report = _normalized(context, detector, selected, run,
                                 perf_counter() - start, applicable=applicable,
                                 skipped=skipped)
        reports.append(report)
        analyzed = {item["file"] for item in report.parsing
                    if item["analysis_status"] == "analyzed"}
        # The sidecar must name the same diagnostics as the report, so it resolves
        # each finding's binding the same way the report did.
        bindings = _source_bindings(run, selected) if run is not None else {}
        partial = {item["file"] for item in report.parsing
                   if item["analysis_status"] == "partial"}
        sidecar["detectors"][detector.detector_id] = {
            "scope_mode": getattr(detector, "ast_scope", "per_file"),
            "status": (
                "not_applicable" if not applicable else
                "failed" if report.status == "failed" else
                "blocked" if report.status == "blocked" and not (analyzed or partial) else
                "partial" if len(analyzed) != len(applicable) or partial else "complete"
            ),
            "applicable_files": len(applicable),
            "analyzed_files": sorted(analyzed),
            "partially_inspected_files": sorted(partial),
            "source_sha256": {u.path: u.sha256 for u in applicable},
            "unexamined": [
                {"file": item["file"], "parse_status": item["status"],
                 "reason": item["analysis_reason"],
                 "analysis_status": item["analysis_status"]}
                for item in report.parsing if item["analysis_status"] != "analyzed"
            ],
            "inspected_files": sorted(analyzed | partial),
            "not_analyzed_files": [item["file"] for item in report.parsing
                                   if item["analysis_status"] == "not_analyzed"],
            "coverage_counts": {
                "complete": len(analyzed), "partial": len(partial),
                "not_analyzed": len(applicable) - len(analyzed) - len(partial),
            },
            "coverage_semantics": "scope_files counts inspection; analyzed_files is complete analysis; partial stays unknown",
            "evidence_obligations": (
                [
                    {"diagnostic_id": _diagnostic_id(detector.detector_id, finding,
                                                 bindings[finding]),
                     "file": finding.file,
                     "source_sha256": next(u.sha256 for u in applicable if u.path == finding.file),
                     "analysis_status": (
                         "partial" if finding.file in partial else "analyzed"
                     ),
                     "source_binding": {
                         "repository": context.request.repository,
                         "commit": context.request.commit,
                         "snapshot_sha256": context.request.snapshot_sha256,
                         "profile_id": context.request.profile_id,
                         "detector_id": detector.detector_id,
                         "detector_version": detector.version,
                         "rule_id": finding.rule_id,
                         "file": finding.file,
                         "source_sha256": next(u.sha256 for u in applicable if u.path == finding.file),
                     },
                     "consequence_impact": finding.consequence_impact,
                     "consequence_cwe": finding.consequence_cwe,
                     "model_version": getattr(detector, "model_version", None),
                     "obligations": [
                         {"kind": obligation.kind, "description": obligation.description,
                          "status": obligation.status}
                         for obligation in finding.evidence_obligations
                     ]}
                    for finding in run.findings
                ] if run is not None and error is None else []
            ),
        }
    return reports, sidecar


def run_all(context: ScanContext, registry: DetectorRegistry):
    """Backwards-compatible M0/M1 interface."""
    return run_all_with_coverage(context, registry)[0]
