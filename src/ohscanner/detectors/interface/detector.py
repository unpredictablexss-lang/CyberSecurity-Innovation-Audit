"""Interface-track adapter for the implemented ohscanner-core contract.

This module does not register itself, change the catalog, run tools, or create
new global schemas. Import of the core contract is deferred until execution,
so main can carry the interface implementation before core is merged.
"""
from src.ohscanner.detectors.interface.ipc_repository import RepositoryIndex


class IpcPermissionDetector:
    detector_id = "ohscanner.interface.permission"
    version = "0.1.0"
    supported_languages = ("cpp",)
    required_facts = ("ast",)
    ast_scope = "whole_scope"

    def detect(self, context, units):
        try:
            from src.ohscanner.contracts import DetectorRun, DetectorFinding, EvidenceObligation
        except ImportError as error:
            raise RuntimeError("Requires reviewed ohscanner-core contracts; not yet present on main") from error
        outlines = context.shared_facts.get("ast", {})
        for unit in units:
            if unit.parse_status != "complete" or outlines.get(unit.path, {}).get("parse_status") != "complete":
                return DetectorRun(self.detector_id, self.version, "blocked",
                    limitations=("Whole-scope syntax requires complete supplied AST for every C++ unit.",))
        if not units:
            return DetectorRun(self.detector_id, self.version, "blocked",
                limitations=("No C++ source units supplied.",))
        try:
            index = RepositoryIndex({u.path: u.text.encode("utf8") for u in units},
                                    context.request.repository, context.request.commit)
        except ValueError as error:
            return DetectorRun(self.detector_id, self.version, "blocked", limitations=(str(error),))
        if any(tree.root_node.has_error for tree in index.trees.values()):
            return DetectorRun(self.detector_id, self.version, "blocked",
                limitations=("Detector-specific source syntax disagrees with complete frontend coverage.",))
        inventory = index.inventory()
        findings = []
        for row in inventory["entries"]:
            permission_helpers = {q["call_chain"][1] for q in row["requirements"] if len(q["call_chain"]) > 1}
            for guard in row["guard_relationships"]:
                if (guard["resolved_to"] not in permission_helpers
                        or guard.get("check_result_relation") != "negated_boolean_in_condition"
                        or guard.get("consequence_terminates_syntax") is not False):
                    continue
                findings.append(DetectorFinding(
                    file=guard["file"], line=guard["line"], symbol=row["entry"]["handler"],
                    rule_id="interface.permission.denial-without-structural-return",
                    message=("Syntax review candidate: a source-derived permission helper appears in "
                             "a negated condition whose consequence has no structural return. "
                             "Later exit, throwing, macro effects, sensitive operation and actual "
                             "authorization policy remain unverified."), evidence_type="syntax",
                    evidence_obligations=(
                        EvidenceObligation("authorization_policy", "Confirm which caller requires which permission."),
                        EvidenceObligation("denial_control_flow", "Prove denial reaches a sensitive operation despite all later guards/exits."),
                        EvidenceObligation("caller_identity", "Verify token provenance, aliases and IPC identity across calls."),
                        EvidenceObligation("macro_and_call_coverage", "Resolve macro side effects, callbacks and dynamic targets."),
                    ),
                ))
        return DetectorRun(self.detector_id, self.version, "completed",
            analyzed_files=tuple(u.path for u in units), findings=tuple(findings), limitations=(
                "Completed means supplied complete syntax examined, not full program semantic coverage or safety.",
                "Source-derived constraints are observations, not an independent official authorization policy.",
                "Cross-file targets, tokens, macro effects and branch feasibility retain documented unknowns.",
                f"Observed {len(inventory['entries'])} source dispatch entries; zero findings is not proof of security.",
                "Interface algorithm uses local detailed Tree-sitter syntax because core outlines omit dispatcher and branch nodes; no competing global frontend/IR is introduced.",
            ))
