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
from .identity import build_identity_record, line_byte_range


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
    digest = sha256(("|".join((source_sha256, finding.file, str(finding.line),
                               finding.rule_id, finding.message))).encode("utf-8")).hexdigest()[:16]
    return f"{detector_id}:{digest}"


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
        if finding.source_sha256 and finding.source_sha256 != unit.sha256:
            raise ValueError("finding source hash does not match the analyzed source")
        diagnostic_id = _diagnostic_id(detector.detector_id, finding, unit.sha256)
        byte_start, byte_end = line_byte_range(unit.text, finding.line)
        blob_oids = context.shared_facts.get("source_blob_oid", {})
        archive_bindings = context.shared_facts.get("source_archive_binding", {})
        observation = {
            "repository": context.request.repository,
            "commit": context.request.commit,
            "snapshot_sha256": context.request.snapshot_sha256,
            "profile_id": context.request.profile_id,
            "legacy_diagnostic_id": diagnostic_id,
            "detector_id": detector.detector_id,
            "detector_version": detector.version,
            "rule_id": finding.rule_id,
            "rule_version": finding.rule_version,
            "rule_lineage_id": finding.rule_lineage_id,
            "file": finding.file,
            "line": finding.line,
            "message": finding.message,
            "source_blob_oid": blob_oids.get(finding.file),
            "source_archive_binding": archive_bindings.get(finding.file),
            "source_sha256": unit.sha256,
            "byte_start": byte_start,
            "byte_end": byte_end,
            "symbol_identity": finding.symbol_identity,
            "ast_fingerprint": finding.ast_fingerprint,
            "identity_quality": finding.identity_quality,
        }
        identity_record = build_identity_record(observation)
        if diagnostic_id in seen_ids:
            raise ValueError("duplicate finding identity")
        seen_ids.add(diagnostic_id)
        findings.append(ToolDiagnostic(
            diagnostic_id=diagnostic_id, provider=detector.detector_id,
            evidence_type=finding.evidence_type, file=finding.file, line=finding.line,
            column=finding.column, rule_id=finding.rule_id, severity="unassessed",
            message=finding.message, candidate_cwe=finding.candidate_cwe,
            confidence="unassessed", symbol=finding.symbol,
            source_sha256=unit.sha256, consequence_impact=finding.consequence_impact,
            consequence_cwe=finding.consequence_cwe,
            finding_identity_id=identity_record["stable"]["id"],
            occurrence_id=identity_record["occurrence"]["id"],
            finding_identity=identity_record,
            source_archive_binding=archive_bindings.get(finding.file)))
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
        return "failed" if per_file.get(path) == "failed" else "not_analyzed"

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
        schema_version=2, run_id=context.request.request_id + ":" + detector.detector_id,
        tool=detector.detector_id, tool_version=detector.version,
        target_id=context.request.target_id, commit=context.request.commit,
        scope_files=len(completed | partly_inspected),
        scope_loc=sum(len(paths[p].text.splitlines()) for p in completed | partly_inspected),
        status=run.status, elapsed_seconds=elapsed, diagnostics=findings,
        limitations=limitations, parsing=parsing,
    )


def _run_independent_files(context, detector, selected, result_cache):
    """Run/cache only detector results whose contract is explicitly per-Blob."""
    outcomes = []
    for unit in selected:
        try:
            run = result_cache.load(detector, context, unit)
        except Exception:
            # A cache is only an optimization. Any cache implementation or
            # filesystem error must reduce to ordinary detection.
            result_cache.stats["read_errors"] += 1
            result_cache.stats["misses"] += 1
            run = None
        if run is None:
            run = detector.detect(context, (unit,))
            if not isinstance(run, DetectorRun):
                raise ValueError("detector must return DetectorRun")
            if run.detector_id != detector.detector_id or run.version != detector.version:
                raise ValueError("detector identity mismatch")
            if (any(path != unit.path for path in run.analyzed_files)
                    or any(item.file != unit.path for item in run.findings)
                    or any(path != unit.path for path, _ in run.file_outcomes)):
                raise ValueError("source-only detector returned data outside its one-file scope")
            if run.status == "completed":
                if (run.analyzed_files != (unit.path,)
                        or (run.file_outcomes and run.file_outcomes != ((unit.path, "complete"),))):
                    raise ValueError("source-only detector violated its one-file result contract")
                try:
                    result_cache.store(detector, context, unit, run)
                except Exception:
                    result_cache.stats["write_skipped"] += 1
        outcomes.append((unit, run))
    statuses = {run.status for _, run in outcomes}
    status = "failed" if "failed" in statuses else "blocked" if "blocked" in statuses else "completed"
    analyzed = set()
    findings, limitations, per_file = [], set(), []
    for unit, run in outcomes:
        analyzed.update(run.analyzed_files)
        findings.extend(run.findings)
        limitations.update(run.limitations)
        if run.status == "completed":
            state = "complete"
        elif unit.path in run.analyzed_files:
            state = "partial"
        elif run.status == "failed":
            state = "failed"
        else:
            state = "not_analyzed"
        per_file.append((unit.path, state))
    return DetectorRun(
        detector.detector_id, detector.version, status,
        analyzed_files=tuple(sorted(analyzed)), findings=tuple(findings),
        limitations=tuple(sorted(limitations)), file_outcomes=tuple(per_file),
    )


def run_all_with_coverage(context: ScanContext, registry: DetectorRegistry,
                          per_file_result_cache=None, detector_checkpoints=None):
    """Return normalized reports plus per-detector coverage and obligations.

    First-party results emit v2; historical v1 results remain readable. In particular, 'completed'
    describes successful work on ELIGIBLE files, not whole-component safety.
    A file in partial AST is not counted as a miss, even if other files ran.
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
        cached_coverage = None
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
        if run is None and detector_checkpoints is not None:
            try:
                cached = detector_checkpoints.load(context, detector, applicable)
            except Exception:
                detector_checkpoints.stats["read_errors"] += 1
                cached = None
            if cached is not None:
                report, cached_coverage = cached
                report.run_id = context.request.request_id + ":" + detector.detector_id
        if run is None and cached_coverage is None:
            try:
                if (per_file_result_cache is not None
                        and getattr(detector, "incremental_cache_policy", None)
                        == "git_blob_single_file_v1"):
                    run = _run_independent_files(context, detector, selected,
                                                 per_file_result_cache)
                else:
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
        elif cached_coverage is None:
            report = _normalized(context, detector, selected, run,
                                 perf_counter() - start, applicable=applicable,
                                 skipped=skipped)
        reports.append(report)
        if cached_coverage is not None:
            sidecar["detectors"][detector.detector_id] = cached_coverage
            continue
        analyzed = {item["file"] for item in report.parsing
                    if item["analysis_status"] == "analyzed"}
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
                "not_analyzed": sum(i["analysis_status"] == "not_analyzed" for i in report.parsing),
                "failed": sum(i["analysis_status"] == "failed" for i in report.parsing),
            },
            "coverage_semantics": "scope_files counts inspection; analyzed_files is complete analysis; partial stays unknown",
            "evidence_obligations": (
                [
                    {"diagnostic_id": _diagnostic_id(detector.detector_id, finding,
                        next(u.sha256 for u in applicable if u.path == finding.file)),
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
                     "risk_assessment": finding.risk_assessment,
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
        if detector_checkpoints is not None and report.status == "completed":
            try:
                detector_checkpoints.store(
                    context, detector, report, sidecar["detectors"][detector.detector_id]
                )
            except Exception:
                detector_checkpoints.stats["write_errors"] += 1
    return reports, sidecar


def run_all(context: ScanContext, registry: DetectorRegistry):
    """Backwards-compatible M0/M1 interface."""
    return run_all_with_coverage(context, registry)[0]
