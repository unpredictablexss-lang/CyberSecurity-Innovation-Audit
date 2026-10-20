"""Owner-reviewed single-pass IPC execution adapter; rule logic stays unchanged.

One interpreter sees all eligible C/C++ units together, preserving the team's
bounded dispatch/macro context. Partial syntax stays partial in the sidecar.
"""
from dataclasses import replace

from src.ohscanner.contracts import DetectorRun, EvidenceObligation
from .analysis import normalize_include_trailing_space, normalize_syntax, parses_clean
from .detector import IpcInterfaceDetector
import tree_sitter_c
import tree_sitter_cpp


_PARTIAL_PROOF = EvidenceObligation(
    "parse_completeness_impact",
    "Review parser errors and surrounding control/call dependencies; a partial "
    "tree may hide guards or paths even when errors are distant from this candidate.",
)


class M2IpcInterfaceDetector(IpcInterfaceDetector):
    """Keep one public detector ID; express execution depth per file."""

    def detect(self, context, units):
        ast = context.shared_facts.get("ast", {})
        recovered_include_paths = set()
        for unit in units:
            if (unit.language not in self.supported_languages or unit.parse_status != "partial"
                    or unit.path not in ast):
                continue
            raw = unit.text.encode("utf-8")
            recovered = normalize_include_trailing_space(raw)
            grammar = tree_sitter_c.language() if unit.language == "c" else tree_sitter_cpp.language()
            # This changes only B's private parse copy. The shared SourceUnit and
            # runner coverage stay partial, so no detector-local recovery can turn
            # incomplete shared coverage into a global complete/safe claim.
            if (recovered != raw and normalize_syntax(recovered) == recovered
                    and parses_clean(recovered, grammar)):
                recovered_include_paths.add(unit.path)
        eligible = tuple(u for u in units if u.language in self.supported_languages
                         and u.parse_status in ("complete", "partial") and u.path in ast)
        unavailable = {u.path for u in units} - {u.path for u in eligible}
        if not eligible:
            return DetectorRun(
                self.detector_id, self.version, "blocked",
                file_outcomes=tuple((u.path, "not_analyzed") for u in units),
                limitations=("No supported unit has an available complete/partial AST outline.",),
            )
        result = super().detect(context, eligible)
        eligible_paths = {u.path for u in eligible}
        if set(result.analyzed_files) - eligible_paths:
            raise ValueError("IPC engine reported inspection outside the eligible source scope")
        if any(f.file not in result.analyzed_files for f in result.findings):
            raise ValueError("IPC engine emitted a candidate without source inspection")
        partial_paths = {u.path for u in eligible if u.parse_status == "partial"}
        outcomes = tuple(
            (u.path, "not_analyzed" if u.path not in result.analyzed_files else
             "partial" if u.path in partial_paths or result.status == "failed" else "complete")
            for u in units
        )
        findings = tuple(
            replace(f, evidence_obligations=f.evidence_obligations + (_PARTIAL_PROOF,))
            if f.file in partial_paths else f
            for f in result.findings
        )
        status = ("failed" if result.status == "failed" else
                  "completed" if result.analyzed_files else "blocked")
        return replace(
            result, status=status, file_outcomes=outcomes, findings=findings,
            limitations=result.limitations + (
                "Owner M2 adapter: single interpretation pass; partial source inspection is not full analysis.",
                f"Unavailable AST units: {len(unavailable)}; cross-file context from these units is unknown.",
            ) + (("B IPC private syntax copy recovered one exact include-line ending for interpretation; "
                  "shared parse coverage remains partial and candidate obligations stay unknown: "
                  + ", ".join(sorted(recovered_include_paths)) + ".",)
                 if recovered_include_paths else ()),
        )
