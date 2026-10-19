"""Ark Runtime candidate detector with source-identity-independent scope.

Applicability is established from parsed owner/method/signature semantics. A
source commit, path, Git blob, and SHA-256 are verified as input provenance but
are not pre-enumerated in the model. Partial or unsupported syntax stays
partial/unknown; this detector never upgrades it to safe.
"""
import json
from hashlib import sha1

from src.ohscanner.contracts import DetectorFinding, DetectorRun, EvidenceObligation
from .analysis import analyze_unit, has_type_origin_flow
from .exception_guard import analyze_exception_guard
from .receiver_guard import analyze_receiver_guard
from .model import (CALL_INFO_EXCEPTION_RULE_ID, DETECTOR_ID, EXCEPTION_GUARD_RULE_ID,
                    RECEIVER_TYPE_GUARD_RULE_ID, RUNTIME_EXCEPTION_RULE_ID,
                    RULE_ID, SIZE_OVERFLOW_RULE_ID, AnalysisBudget)
from .runtime_exception import (analyze_runtime_exception_propagation,
                                analyze_call_info_construction_guard,
                                has_call_info_constructor)
from .syntax import parse_functions
from .size_overflow import analyze_size_flows, size_overflow_result_from_flows
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
        self._semantic_cache = {}

    def _context_supported(self, context):
        return (context.request.repository == self.model.source_repository
                and context.request.provenance == "git_object"
                and context.request.profile_id == "light-ast")

    def _semantic_targets(self, unit, source_units=()):
        if unit.language not in self.supported_languages:
            return ()
        cache_key = (unit.path, unit.sha256)
        cached = self._semantic_cache.get(cache_key)
        if cached is not None:
            return cached[0]
        try:
            tree, functions = parse_functions(unit.text.encode("utf-8"))
        except (ValueError, RuntimeError, UnicodeError):
            return ()
        names = set(self.model.callers) | set(self.model.exception_guard_callers)
        size_flows, size_limitations = analyze_size_flows(
            unit.text, functions=functions, parse_complete=(unit.parse_status == "complete"
                                                            and not tree.root_node.has_error))
        size_targets = {flow.function for flow in size_flows}
        selected = tuple(fn for fn in functions
                         if fn.qualified_name in names or has_type_origin_flow(fn, self.model))
        if selected:
            targets = selected + tuple(
                fn for fn in functions
                if fn.qualified_name in size_targets
                and fn not in selected)
        elif size_targets:
            targets = tuple(fn for fn in functions if fn.qualified_name in size_targets)
        else:
            targets = ()
        runtime_exception_result = None
        effect_tokens = tuple(spec[0].split("::")[-1]
                              for spec in self.model.runtime_effect_calls)
        if (not selected and not size_targets
                and any(token in unit.text for token in effect_tokens)
                and any(name in unit.text for name in self.model.runtime_sensitive_result_methods)):
            runtime_exception_result = analyze_runtime_exception_propagation(
                unit, source_units=source_units,
                effect_calls=self.model.runtime_effect_calls,
                sensitive_methods=self.model.runtime_sensitive_result_methods,
                guards=self.model.runtime_exception_guards,
                max_instructions=self.budget.max_instructions)
        call_info_result = None
        creator_tokens = tuple(spec[0].split("::")[-1]
                               for spec in self.model.runtime_call_info_creators)
        if (not selected and not size_targets and runtime_exception_result is None
                and any(token in unit.text for token in creator_tokens)
                and any(name in unit.text for name in self.model.runtime_call_info_sensitive_methods)
                and has_call_info_constructor(unit, self.model.runtime_call_info_creators,
                                              functions=functions)):
            call_info_result = analyze_call_info_construction_guard(
                unit, source_units=source_units,
                creators=self.model.runtime_call_info_creators,
                sensitive_methods=self.model.runtime_call_info_sensitive_methods,
                guards=self.model.runtime_exception_guards,
                max_instructions=self.budget.max_instructions)
        if not selected and not size_targets and runtime_exception_result is not None and runtime_exception_result.file_outcome != "not_analyzed":
            targets = tuple(functions)
        elif (not selected and not size_targets and call_info_result is not None
              and call_info_result.file_outcome != "not_analyzed"):
            targets = tuple(functions)
        self._semantic_cache[cache_key] = (targets, size_flows, size_limitations,
                                            runtime_exception_result, call_info_result)
        return targets

    def select_applicable_units(self, context, units):
        """Select by stable code semantics, never by a post-selection exact bind."""
        self._semantic_cache.clear()
        if not self._context_supported(context):
            return ()
        return tuple(unit for unit in units if self._semantic_targets(unit, units))

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
            targets = self._semantic_targets(unit, context.units)
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
            has_type_target = any(fn.qualified_name in target_type_names
                                  or has_type_origin_flow(fn, self.model) for fn in targets)
            if has_type_target:
                result = analyze_unit(unit, model=self.model, budget=self.budget,
                                      research_partial=unit.parse_status == "partial")
                results.append((RULE_ID, result))
            (_, size_flows, size_limitations,
             runtime_exception_result, call_info_result) = self._semantic_cache.get(
                (unit.path, unit.sha256), (targets, (), (), None, None))
            size_target_names = {flow.function for flow in size_flows}
            if any(fn.qualified_name in size_target_names for fn in targets):
                result = size_overflow_result_from_flows(
                    unit, self.model.digest, size_flows, size_limitations)
                results.append((SIZE_OVERFLOW_RULE_ID, result))
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
            if targets:
                result = analyze_receiver_guard(unit, budget=self.budget)
                results.append((RECEIVER_TYPE_GUARD_RULE_ID, result))
            if runtime_exception_result is not None and runtime_exception_result.file_outcome != "not_analyzed":
                result = runtime_exception_result
                results.append((RUNTIME_EXCEPTION_RULE_ID, result))
            if call_info_result is not None and call_info_result.file_outcome != "not_analyzed":
                result = call_info_result
                results.append((CALL_INFO_EXCEPTION_RULE_ID, result))

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
                    elif rule_id == RUNTIME_EXCEPTION_RULE_ID:
                        obligations = (
                            ("exception_effect_semantics", "Verify the callback call can leave the runtime thread with a pending exception and that the configured macro checks that same thread."),
                            ("control_flow_dominance", "Review the path proof; the current rule handles only direct same-compound result use and a resolved guard or early exception exit."),
                            ("runtime_impact", "Establish a reachable callback outcome that causes the unsafe conversion and concrete product impact."),
                            ("product_binding", "Bind the exact source revision and actual macro/profile to a shipped product."),
                        )
                        message = "Candidate only: callback completion may reach a result conversion before a dominating exception exit. trace=" + trace
                    elif rule_id == CALL_INFO_EXCEPTION_RULE_ID:
                        obligations = (
                            ("constructor_failure_semantics", "Verify the call-info constructor can fail by setting this thread's pending exception and returning an unusable pointer."),
                            ("pointer_use_path", "Review the pointer reaching the sensitive member call and confirm the pending-exception guard dominates that use."),
                            ("runtime_reachability", "Establish a reachable stack/resource failure condition and concrete runtime impact."),
                            ("product_binding", "Bind the source, macro definition, dependencies and stack-check build profile to a shipped product."),
                        )
                        message = "Candidate only: call-info construction may leave a pending exception before the result pointer is used. trace=" + trace
                    elif rule_id == SIZE_OVERFLOW_RULE_ID:
                        obligations = (
                            ("integer_range_proof", "Verify runtime ranges and C++ integer conversions establish a real wrap on the allocation-size multiplication."),
                            ("allocation_copy_control_flow", "Verify the allocation result is the copy destination and the operand-bounded loop reaches the write sink."),
                            ("runtime_impact", "Establish that a reachable input causes a write beyond the allocated buffer and determine the impact."),
                            ("product_binding", "Bind source revision, dependencies, build flags, and allocation limits to an actual product."),
                            ("isolated_validation", "Run the upstream regression only with an authorized isolated build and resource limit."),
                        )
                        message = "Candidate only: an integer product narrower than its source factors flows to a buffer allocation, while a copy loop is bounded by one source factor. Range and control-flow proof is incomplete. trace=" + trace
                    elif rule_id == RECEIVER_TYPE_GUARD_RULE_ID:
                        obligations = (
                            ("guard_semantics", "Verify the runtime type predicate accepts only objects valid for the backing-buffer accessor."),
                            ("runtime_path_feasibility", "Establish that attacker-reachable input can reach the unguarded sensitive operation."),
                            ("runtime_impact", "Establish concrete crash, corruption, or security impact under an isolated runtime test."),
                            ("product_binding", "Bind the exact source revision and build configuration to an affected shipped product."),
                        )
                        message = "Candidate only: backing-buffer access is reachable without a dominating same-receiver runtime type guard. trace=" + trace
                    else:
                        obligations = (
                            ("model_applicability", "Verify exact symbols, signatures, macros, and model semantics in the product build."),
                            ("runtime_path_feasibility", "Prove the destination runtime type on the generated path and its relation to the supplied type token."),
                            ("security_impact", "Establish realistic entry, attacker control, and concrete CIA impact."),
                            ("isolated_validation", "Reproduce and revalidate only in an authorized isolated environment."),
                        )
                        message = "Candidate only: TypedArray destination and type-token origins differ after a creation that may produce a different runtime type under the bounded model. trace=" + trace
                    if unit.parse_status == "partial":
                        obligations += (("parse_completeness_impact", "Partial translation-unit parsing may hide declarations, macros, or effects; retain this as unknown local evidence."),)
                    findings.append(DetectorFinding(
                        file=unit.path, line=item.line, column=item.column,
                        rule_id=rule_id, message=message, evidence_type="syntax",
                        candidate_cwe=("CWE-190" if rule_id == SIZE_OVERFLOW_RULE_ID else
                                       "CWE-843" if rule_id == RULE_ID else
                                       "CWE-755" if rule_id == RUNTIME_EXCEPTION_RULE_ID else
                                       "CWE-476" if rule_id == CALL_INFO_EXCEPTION_RULE_ID else None),
                        symbol=item.symbol, source_sha256=unit.sha256,
                        evidence_obligations=tuple(EvidenceObligation(kind, description)
                                                   for kind, description in obligations),
                    ))

        incomplete = any(state != "complete" for _, state in outcomes)
        self._semantic_cache.clear()
        return DetectorRun(
            self.detector_id, self.version,
            "failed" if failed else "blocked" if incomplete else "completed",
            tuple(inspected), tuple(findings),
            tuple(sorted(set(limitations + [
                "Semantic applicability is bounded to declared Ark Runtime owner/method/signature profiles; no preprocessor, whole-program, product-build, or exploitability proof.",
            ]))), tuple(outcomes))
