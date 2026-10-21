"""Reviewed M2 adapters for teammate A's unchanged narrow C++ candidate engines.

Algorithms are vendored unchanged from the team's A consolidation branch;
the adapters only normalize file-level execution and missing proof obligations.
"""
from dataclasses import replace

from src.ohscanner.contracts import DetectorRun, EvidenceObligation
from .lifetime_detector import LifetimeOwnershipGuardDetector
from .shared_ptr_race_detector import SharedPtrRaceDetector


_PROOF = {
    "ohscanner.cpp.lifetime": (
        EvidenceObligation("owner_alias_identity", "Verify alias identity and owner lifetime across full C++ semantics."),
        EvidenceObligation("control_flow_reachability", "Show reset and dereference are reachable on the same executable path."),
        EvidenceObligation("product_build_context", "Establish macros, template instantiation and target build configuration."),
        EvidenceObligation("security_impact", "Verify attacker control and actual memory safety impact in an isolated target."),
    ),
    "ohscanner.cpp.shared_ptr_race": (
        EvidenceObligation("synchronization_proof", "Resolve lock and atomic semantics across all accesses."),
        EvidenceObligation("thread_interleaving", "Demonstrate feasible concurrent accesses to the same object."),
        EvidenceObligation("product_build_context", "Establish real build and template instantiation context."),
        EvidenceObligation("security_impact", "Verify reachable trigger and concrete CIA impact independently."),
    ),
}


class _AFileScopedAdapter:
    """Call original A detector per eligible file without overriding its rule logic."""

    required_facts = ("ast",)  # Shared AST eligibility, not a claim to consume CFG/IR.
    ast_scope = "per_file"
    supported_languages = ("cpp",)
    # Each inner call receives exactly one SourceUnit and its result is then
    # normalized for that same file. The cache's engine digest binds this
    # adapter and the complete ohscanner package source. Keep this opt-in only
    # while the adapter preserves the one-file boundary.
    incremental_cache_policy = "git_blob_single_file_v1"
    incremental_cache_version = "m2-file-adapter-v1"
    incremental_cache_facts = ("ast",)
    implementation = None

    def __init__(self):
        self.inner = self.implementation()
        self.detector_id = self.inner.detector_id
        self.version = self.inner.version

    def detect(self, context, units):
        outcomes, inspected, findings, limitations = [], [], [], []
        has_failure = False
        has_gap = False
        for unit in sorted(units, key=lambda item: item.path):
            if unit.language not in self.supported_languages or unit.parse_status != "complete":
                outcomes.append((unit.path, "not_analyzed"))
                has_gap = True
                limitations.append(unit.path + ": complete C++ AST eligibility is required.")
                continue
            result = self.inner.detect(context, (unit,))
            if result.detector_id != self.detector_id or result.version != self.version:
                raise ValueError("A detector changed its declared identity")
            if set(result.analyzed_files) - {unit.path}:
                raise ValueError("A detector analyzed a file outside its supplied scope")
            if any(finding.file != unit.path for finding in result.findings):
                raise ValueError("A detector emitted a candidate outside its supplied file")
            if result.findings and unit.path not in result.analyzed_files:
                raise ValueError("A detector emitted candidates without source inspection")
            if result.status == "completed":
                if result.analyzed_files != (unit.path,):
                    raise ValueError("A detector completed without recording full source scope")
                outcome = "complete"
            elif result.status == "failed":
                outcome = "failed"
                has_failure = has_gap = True
            else:
                outcome = "partial" if unit.path in result.analyzed_files else "not_analyzed"
                has_gap = True
            outcomes.append((unit.path, outcome))
            if unit.path in result.analyzed_files:
                inspected.append(unit.path)
            if result.status != "failed":
                findings.extend(
                    replace(finding, evidence_obligations=_PROOF[self.detector_id])
                    for finding in result.findings
                )
            limitations.extend(result.limitations)
            if outcome != "complete":
                limitations.append(unit.path + ": " + outcome + "; no safety verdict.")
        status = "failed" if has_failure else "blocked" if has_gap else "completed"
        limitations.append("First-party A algorithm: syntax candidates only; no CVE or validated vulnerability.")
        return DetectorRun(
            self.detector_id, self.version, status,
            analyzed_files=tuple(sorted(inspected)),
            findings=tuple(findings),
            limitations=tuple(sorted(set(limitations))),
            file_outcomes=tuple(outcomes),
        )


class M2LifetimeDetector(_AFileScopedAdapter):
    implementation = LifetimeOwnershipGuardDetector


class M2SharedPtrRaceDetector(_AFileScopedAdapter):
    implementation = SharedPtrRaceDetector
