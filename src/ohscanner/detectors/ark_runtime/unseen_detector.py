"""Ark Runtime candidate detector with source-identity-independent scope.

Applicability is established from parsed owner/method/signature semantics. A
source commit, path, Git blob, and SHA-256 are verified as input provenance but
are not pre-enumerated in the model. Partial or unsupported syntax stays
partial/unknown; this detector never upgrades it to safe.
"""
import json
from hashlib import sha1

from src.ohscanner.contracts import DetectorFinding, DetectorRun, EvidenceObligation
from .analysis import analyze_unit
from .exception_guard import analyze_exception_guard
from .model import DETECTOR_ID, EXCEPTION_GUARD_RULE_ID, RULE_ID, AnalysisBudget
from .syntax import parse_functions
from .unseen_model import UNSEEN_VERSION, UnseenRuntimeTypeModel


class ArkRuntimeUnseenTypeSafetyDetector:
    detector_id = DETECTOR_ID
    version = UNSEEN_VERSION
    model_version = UNSEEN_VERSION
    supported_languages = ("cpp",)
    required_facts = ()
    ast_scope = "per_file"

    def __init__(self, model=None, budget=None):
        self.model = model or UnseenRuntimeTypeModel()
        self.budget = budget or AnalysisBudget()

    def _context_supported(self, context):
        return (context.request.repository == self.model.source_repository
                and context.request.provenance == "git_object"
                and context.request.profile_id == "light-ast")

    def _semantic_targets(self, unit):
        if unit.language not in self.supported_languages:
            return ()
        try:
            _, functions = parse_functions(unit.text.encode("utf-8"))
        except (ValueError, RuntimeError, UnicodeError):
            return ()
        names = set(self.model.callers) | set(self.model.exception_guard_callers)
        return tuple(fn for fn in functions if fn.qualified_name in names)

    def select_applicable_units(self, context, units):
        """Select by stable code semantics, never by a post-selection exact bind."""
        if not self._context_supported(context):
            return ()
        return tuple(unit for unit in units if self._semantic_targets(unit))

    def detect(self, context, units):
        if not self._context_supported(context):
            return DetectorRun(self.detector_id, self.version, "blocked", limitations=(
                "unseen_contract_requires_pinned_ark_runtime_git_source_and_light_ast",))

        findings, outcomes, inspected, limitations = [], [], [], []
        failed = False
        bound = {unit.path: unit.sha256 for unit in context.units}
        ast = context.shared_facts.get("ast", {})
        blob_oids = context.shared_facts.get("source_blob_oid", {})
        for unit in sorted(units, key=lambda item: item.path):
            if bound.get(unit.path) != unit.sha256:
                raise ValueError("detector_input_outside_bound_context")
            targets = self._semantic_targets(unit)
            if not targets:
                outcomes.append((unit.path, "not_analyzed"))
                limitations.append(unit.path + ": no semantically applicable owner/method was resolved")
                continue

            raw = unit.text.encode("utf-8")
            git_blob = sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
            if (unit.language not in self.supported_languages
                    or not unit.sha256
                    or blob_oids.get(unit.path) != git_blob):
                outcomes.append((unit.path, "not_analyzed"))
                limitations.append(unit.path + ": Git blob provenance does not match source bytes")
                continue
            ast_entry = ast.get(unit.path)
            if (not isinstance(ast_entry, dict)
                    or ast_entry.get("parse_status") != unit.parse_status
                    or unit.parse_status not in ("complete", "partial")):
                outcomes.append((unit.path, "not_analyzed"))
                limitations.append(unit.path + ": shared AST status is missing or inconsistent")
                continue

            results = []
            target_type_names = set(self.model.callers)
            has_type_target = any(fn.qualified_name in target_type_names for fn in targets)
            if has_type_target:
                result = analyze_unit(unit, model=self.model, budget=self.budget,
                                      research_partial=unit.parse_status == "partial")
                results.append((RULE_ID, result))
            exception_names = set(self.model.exception_guard_callers)
            if any(fn.qualified_name in exception_names for fn in targets):
                result = analyze_exception_guard(
                    unit, creator_name=self.model.exception_guard_creator[0],
                    creator_arity=self.model.exception_guard_creator[1],
                    sink_name=self.model.exception_guard_sink[0],
                    sink_arity=self.model.exception_guard_sink[1],
                    sink_glue_arg=self.model.exception_guard_sink[2],
                    sink_object_arg=self.model.exception_guard_sink[3],
                    caller_names=self.model.exception_guard_callers,
                    caller_types=self.model.exception_guard_caller_types,
                    budget=self.budget)
                results.append((EXCEPTION_GUARD_RULE_ID, result))

            file_outcome = (
                "complete" if all(result.file_outcome == "complete" for _, result in results)
                else "partial" if any(result.file_outcome in ("complete", "partial") for _, result in results)
                else "not_analyzed" if all(result.file_outcome == "not_analyzed" for _, result in results)
                else "failed")
            outcomes.append((unit.path, file_outcome))
            if file_outcome in ("complete", "partial"):
                inspected.append(unit.path)
            failed |= any(result.status == "failed" for _, result in results)

            for rule_id, result in results:
                limitations.extend(unit.path + ": " + item for item in result.limitations)
                for item in result.observations:
                    if item.kind != "candidate":
                        continue
                    trace = json.dumps({
                        "target": item.target_identity,
                        "token_origin": item.token_origin,
                        "token_line": item.token_line,
                        "creation_line": item.creation_line,
                        "generated_path": item.path,
                        "constraints": item.constraints,
                        "model_sha256": result.model_digest or self.model.digest,
                        "function_region": [item.region_start_byte, item.region_end_byte],
                        "unreviewed_effect_sites": item.effect_sites,
                    }, sort_keys=True)
                    if rule_id == EXCEPTION_GUARD_RULE_ID:
                        obligations = (
                            ("exception_path_semantics", "Verify the allocation may leave a pending exception and that the sensitive result use runs before the exception return."),
                            ("runtime_impact", "Establish whether a reachable runtime path causes product impact."),
                            ("product_binding", "Bind the exact source revision and build configuration to a shipped product."),
                            ("isolated_validation", "Reproduce and revalidate only in an authorized isolated environment."),
                        )
                        message = "Candidate only: allocation result may be used on a path with a pending exception. trace=" + trace
                    else:
                        obligations = (
                            ("model_applicability", "Verify exact symbols, signatures, macros, and model semantics in the product build."),
                            ("runtime_path_feasibility", "Prove generated path conditions and species return type in the real runtime."),
                            ("security_impact", "Establish realistic entry, attacker control, and concrete CIA impact."),
                            ("isolated_validation", "Reproduce and revalidate only in an authorized isolated environment."),
                        )
                        message = "Candidate only: TypedArray destination and type-token origin differ under the bounded species model. trace=" + trace
                    if unit.parse_status == "partial":
                        obligations += (("parse_completeness_impact", "Partial translation-unit parsing may hide declarations, macros, or effects; retain this as unknown local evidence."),)
                    findings.append(DetectorFinding(
                        file=unit.path, line=item.line, column=item.column,
                        rule_id=rule_id, message=message, evidence_type="syntax",
                        candidate_cwe="CWE-843" if rule_id == RULE_ID else None,
                        symbol=item.symbol, source_sha256=unit.sha256,
                        evidence_obligations=tuple(EvidenceObligation(kind, description)
                                                   for kind, description in obligations),
                    ))

        incomplete = any(state != "complete" for _, state in outcomes)
        return DetectorRun(
            self.detector_id, self.version,
            "failed" if failed else "blocked" if incomplete else "completed",
            tuple(inspected), tuple(findings),
            tuple(sorted(set(limitations + [
                "Semantic applicability is bounded to declared Ark Runtime owner/method/signature profiles; no preprocessor, whole-program, product-build, or exploitability proof.",
            ]))), tuple(outcomes))
