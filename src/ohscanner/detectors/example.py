"""Auditable C/C++ syntax call-site example (candidate evidence only).

This is NOT a verified security detector. It demonstrates how first-party
detectors consume the common frontend and declare missing proof obligations.
No external tool execution or mutations are performed.
"""
from src.ohscanner.contracts import (
    DetectorFinding, DetectorRun, EvidenceObligation, ScanContext, SourceUnit,
)
from typing import Tuple

_COPY_APIS = frozenset(("strcpy", "strcat", "memcpy", "memmove", "sprintf"))


class CppCopyCallExampleDetector:
    detector_id = "ohscanner.example.cpp.copy-calls"
    version = "0.1.0-example"
    supported_languages = ("c", "cpp")
    required_facts = ("ast", "facts_v1")
    ast_scope = "per_file"
    # This example inventories syntax from one fixed source Blob. It does not
    # consume include resolution, build flags, macros, symbols or other files.
    incremental_cache_policy = "git_blob_single_file_v1"
    incremental_cache_version = "1"
    incremental_cache_facts = ("ast", "facts_v1")

    def detect(self, context: ScanContext, units: Tuple[SourceUnit, ...]) -> DetectorRun:
        syntax_facts = context.shared_facts["facts_v1"]
        findings = []
        for unit in units:
            # Runner must not give us partial AST, and the detector enforces
            # the assumption independently to prevent misleading coverage.
            if unit.parse_status != "complete":
                return DetectorRun(
                    self.detector_id, self.version, "blocked",
                    limitations=("Incomplete AST: cannot evaluate requested source scope.",),
                )
            outline = syntax_facts.get(unit.path)
            if outline is None or outline.get("parse_status") != "complete":
                return DetectorRun(
                    self.detector_id, self.version, "blocked",
                    limitations=("Missing complete AST outline for: " + unit.path,),
                )
            for call in outline.get("calls", ()):
                name = str(call.get("expression", ""))
                if name not in _COPY_APIS:
                    continue
                line = call.get("line")
                if not isinstance(line, int) or line < 1:
                    continue
                findings.append(DetectorFinding(
                    file=unit.path,
                    line=line,
                    rule_id="example.cpp.copy-call-inventory",
                    message=(
                        f"Unverified syntax candidate: call expression {name}; "
                        "destination capacity, source bounds, actual target and "
                        "reachability have NOT been established."
                    ),
                    evidence_type="syntax",
                    evidence_obligations=(
                        EvidenceObligation(
                            "resolved_callee", "Resolve macro/overload and actual invoked target."
                        ),
                        EvidenceObligation(
                            "bounds_proof", "Prove destination/source ranges and capacities."
                        ),
                        EvidenceObligation(
                            "reachability", "Verify executable path and attacker influence."
                        ),
                    ),
                ))
        return DetectorRun(
            self.detector_id, self.version, "completed",
            analyzed_files=tuple(unit.path for unit in units),
            findings=tuple(findings),
            limitations=(
                "EXAMPLE ONLY: inventories selected syntax call expressions; it is not vulnerability detection.",
                "No control flow, call resolution, macro expansion, object size or taint analysis.",
            ),
        )
