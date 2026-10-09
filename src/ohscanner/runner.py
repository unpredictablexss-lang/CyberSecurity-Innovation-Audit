"""Validate, isolate and normalize first-party detector runs to ToolRunResult v1."""

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
        self._detectors[ident] = detector

    def detectors(self):
        return [self._detectors[key] for key in sorted(self._detectors)]


def _normalized(context, detector, selected, run, elapsed, error=None):
    if error:
        run = DetectorRun(detector.detector_id, detector.version, "failed",
                          limitations=(f"Detector failed: {error.__class__.__name__}",))
    if not isinstance(run, DetectorRun):
        raise ValueError("detector must return DetectorRun")
    if run.detector_id != detector.detector_id or run.version != detector.version:
        raise ValueError("detector identity mismatch")
    paths = {unit.path: unit for unit in selected}
    if not set(run.analyzed_files).issubset(paths):
        raise ValueError("reported scope includes unprovided files")
    if run.status == "completed" and set(run.analyzed_files) != set(paths):
        raise ValueError("completed detector skipped a selected source unit")

    findings = []
    seen_ids = set()
    for finding in run.findings:
        if finding.file not in run.analyzed_files:
            raise ValueError("finding outside analyzed scope")
        unit = paths[finding.file]
        if finding.line > len(unit.text.splitlines()):
            raise ValueError("finding location outside source")
        digest = sha256(("|".join((finding.file, str(finding.line),
                                   finding.rule_id, finding.message))).encode("utf-8")).hexdigest()[:16]
        diagnostic_id = f"{detector.detector_id}:{digest}"
        if diagnostic_id in seen_ids:
            raise ValueError("duplicate finding identity")
        seen_ids.add(diagnostic_id)
        findings.append(ToolDiagnostic(
            diagnostic_id=diagnostic_id, provider=detector.detector_id,
            evidence_type=finding.evidence_type, file=finding.file, line=finding.line,
            column=finding.column, rule_id=finding.rule_id, severity="unassessed",
            message=finding.message, candidate_cwe=finding.candidate_cwe,
            confidence="unassessed", symbol=finding.symbol))
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
    if run.status == "blocked":
        limitations.append("Coverage incomplete or unsupported; do not infer safety.")
    if run.status == "failed":
        limitations.append("Detector failed; unexamined scope is unknown.")
    return ToolRunResult(
        schema_version=1, run_id=context.request.request_id + ":" + detector.detector_id,
        tool=detector.detector_id, tool_version=detector.version,
        target_id=context.request.target_id, commit=context.request.commit,
        scope_files=len(run.analyzed_files),
        scope_loc=sum(len(paths[p].text.splitlines()) for p in run.analyzed_files),
        status=run.status, elapsed_seconds=elapsed, diagnostics=findings,
        limitations=limitations,
        parsing=[{"file": unit.path, "status": unit.parse_status,
                  "issues": list(unit.parse_issues)} for unit in selected],
    )


def run_all(context: ScanContext, registry: DetectorRegistry):
    # Verify the provided units still bind to the request's declared fixture manifest.
    # This is synthetic identity verification, not Git commit/tree verification.
    from .fixture import snapshot_digest
    if snapshot_digest(context.units) != context.request.snapshot_sha256:
        raise ValueError("source unit manifest does not match ScanRequest")
    results = []
    for detector in registry.detectors():
        selected = tuple(unit for unit in context.units
                         if unit.language in detector.supported_languages)
        start = perf_counter()
        if not selected:
            run = DetectorRun(detector.detector_id, detector.version, "blocked",
                              limitations=("not_applicable: no source with supported language.",))
            results.append(_normalized(context, detector, selected, run, perf_counter() - start))
            continue
        missing = set(detector.required_facts) - set(context.shared_facts)
        if missing:
            run = DetectorRun(detector.detector_id, detector.version, "blocked",
                              limitations=("Missing required shared facts: " + ", ".join(sorted(missing)),))
            results.append(_normalized(context, detector, selected, run, perf_counter() - start))
            continue
        # The shared AST map may exist while individual translation units failed
        # parsing. A detector that requires complete syntax may not claim success.
        if "ast" in detector.required_facts:
            incomplete = [unit.path for unit in selected if unit.parse_status != "complete"]
            if incomplete:
                run = DetectorRun(detector.detector_id, detector.version, "blocked",
                                  limitations=("Required complete AST unavailable for: "
                                               + ", ".join(incomplete[:8]),))
                results.append(_normalized(context, detector, selected, run, perf_counter() - start))
                continue
        try:
            run = detector.detect(context, selected)
            result = _normalized(context, detector, selected, run, perf_counter() - start)
        except Exception as exc:
            result = _normalized(context, detector, selected, None,
                                 perf_counter() - start, error=exc)
        results.append(result)
    return results
