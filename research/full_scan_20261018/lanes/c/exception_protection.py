"""Narrow research-only probe for pending-exception propagation in one Ark Runtime caller.

This detector is not registered in the product catalog. It reports only the exact
LowerCallStubWithIC CallStub-result replacement pattern; runtime semantics remain obligations.
"""
from dataclasses import dataclass
from hashlib import sha256
import json

from src.ohscanner.contracts import DetectorRun, DetectorFinding, EvidenceObligation
from .syntax import parse_functions, walk

DETECTOR_ID = "ohscanner.ark.runtime.exception_protection"
RULE_ID = "ark.runtime.callstub.pending-exception-propagation"
VERSION = "0.1.0"
TARGET_SYMBOL = "panda::ecmascript::kungfu::SlowPathLowering::LowerCallStubWithIC"
TARGET_PATH = "ecmascript/compiler/slowpath_lowering.cpp"
TARGET_TYPES = ("GateRef", "int", "std::vector<GateRef>")
MODEL = {
    "target_symbol": TARGET_SYMBOL,
    "target_types": TARGET_TYPES,
    "call_name": "builder_.CallStub",
    "unsafe_replacement": "ReplaceHirWithValue",
    "protected_replacement": "ReplaceHirWithPendingException",
    "protected_arguments": ("gate", "builder_.GetState()", "builder_.GetDepend()", "result"),
    "scope": "one exact function in one source path; research only",
}
MODEL_SHA256 = sha256(json.dumps(MODEL, sort_keys=True).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Observation:
    kind: str
    reason: str
    line: int = 0
    symbol: str = TARGET_SYMBOL
    model_sha256: str = MODEL_SHA256


@dataclass(frozen=True)
class AnalysisResult:
    status: str
    file_outcome: str
    observations: tuple = ()
    limitations: tuple = ()


def analyze_unit(unit) -> AnalysisResult:
    """Analyze only the pinned call-result propagation shape, never broad C++ code."""
    if unit.path != TARGET_PATH or unit.language != "cpp":
        return AnalysisResult("not_applicable", "not_analyzed", limitations=("outside_exact_exception_rule_scope",))
    actual_sha = sha256(unit.text.encode("utf-8")).hexdigest()
    if actual_sha != unit.sha256:
        return AnalysisResult("failed", "failed", limitations=("source_hash_mismatch",))
    if unit.parse_status in ("failed", "not_run"):
        return AnalysisResult("blocked", "not_analyzed", limitations=("source_parse_unavailable",))
    try:
        tree, functions = parse_functions(unit.text.encode("utf-8"))
    except (ValueError, RuntimeError) as error:
        return AnalysisResult("failed", "failed", limitations=("parser_failure:" + type(error).__name__,))
    targets = [fn for fn in functions if fn.qualified_name == TARGET_SYMBOL]
    if len(targets) != 1:
        partial = tree.root_node.has_error or unit.parse_status != "complete"
        return AnalysisResult("blocked" if partial else "completed", "not_analyzed",
                              limitations=("target_not_resolved_in_partial_ast" if partial else "not_applicable_to_rule",))
    fn = targets[0]
    partial = tree.root_node.has_error or unit.parse_status != "complete"
    if fn.node.has_error:
        return AnalysisResult("blocked", "not_analyzed", limitations=("target_function_parse_error",))
    if tuple(fn.parameter_types) != TARGET_TYPES:
        return AnalysisResult("blocked", "not_analyzed", limitations=("target_signature_mismatch",))

    callstub_results = {}
    for node in walk(fn.body):
        if node.type != "call_expression" or fn.call_name(node) != MODEL["call_name"]:
            continue
        parent = node.parent
        if parent is None or parent.type != "init_declarator":
            continue
        value = parent.child_by_field_name("value")
        declarator = parent.child_by_field_name("declarator")
        if value != node or declarator is None or declarator.type != "identifier":
            continue
        binding = fn.resolve(fn.text(declarator), declarator)
        if binding:
            callstub_results[binding.identity] = node.start_point[0] + 1

    if not callstub_results:
        outcome = "partial" if partial else "complete"
        limitations = ("source_parse_partial", "no_callstub_result_binding") if partial else ("no_callstub_result_binding",)
        return AnalysisResult("limited" if partial else "completed", outcome, limitations=limitations)

    unsafe, protected = [], []
    for node in walk(fn.body):
        if node.type != "call_expression":
            continue
        name = fn.call_name(node)
        args = fn.arguments(node)
        if not args or args[-1].type != "identifier":
            continue
        binding = fn.resolve(fn.text(args[-1]), args[-1])
        if not binding or binding.identity not in callstub_results:
            continue
        if name == MODEL["unsafe_replacement"] and len(args) == 2:
            unsafe.append(node.start_point[0] + 1)
        elif name == MODEL["protected_replacement"] and len(args) == 4:
            written = tuple(fn.text(arg) for arg in args)
            if written == MODEL["protected_arguments"]:
                protected.append(node.start_point[0] + 1)
            else:
                reason = "protected_replacement_signature_unresolved"
                obs = (Observation("unknown", reason, node.start_point[0] + 1),)
                return AnalysisResult("limited", "partial", obs, (reason,))

    if len(unsafe) == 1 and not protected:
        obs = (Observation("candidate", "callstub_result_replaced_without_pending_exception_propagation", unsafe[0]),)
    elif len(protected) == 1 and not unsafe:
        obs = (Observation("matched", "callstub_result_uses_pending_exception_propagation", protected[0]),)
    elif unsafe or protected:
        obs = (Observation("unknown", "ambiguous_or_mixed_callstub_result_replacements", min(unsafe + protected)),)
    else:
        obs = ()
    limitations = ["exact_symbol_and_call_shape probe; no interprocedural or product-build proof"]
    if partial:
        limitations.append("source_parse_partial")
    if any(item.kind == "unknown" for item in obs):
        limitations.extend(("unresolved_local_observations", "unknown_observation:" + str(obs[0].line) + ":" + obs[0].reason))
    return AnalysisResult("limited" if partial or any(o.kind == "unknown" for o in obs) else "completed",
                          "partial" if partial or any(o.kind == "unknown" for o in obs) else "complete",
                          obs, tuple(sorted(set(limitations))))


class ArkRuntimeExceptionProtectionDetector:
    """Research-only Detector adapter; deliberately not in the production catalog."""
    detector_id = DETECTOR_ID
    version = VERSION
    supported_languages = ("cpp",)
    required_facts = ("ast",)
    ast_scope = "per_file"

    def detect(self, context, units):
        findings, outcomes, analyzed, limitations = [], [], [], []
        bound = {unit.path: unit.sha256 for unit in context.units}
        for unit in sorted(units, key=lambda item: item.path):
            if bound.get(unit.path) != unit.sha256:
                raise ValueError("detector_input_outside_bound_context")
            if unit.language != "cpp" or unit.path != TARGET_PATH:
                outcomes.append((unit.path, "not_analyzed"))
                continue
            if unit.parse_status in ("failed", "not_run") or unit.path not in context.shared_facts.get("ast", {}):
                outcomes.append((unit.path, "not_analyzed"))
                limitations.append(unit.path + ": missing parse or shared AST eligibility evidence")
                continue
            result = analyze_unit(unit)
            outcomes.append((unit.path, result.file_outcome))
            if result.file_outcome in ("complete", "partial"):
                analyzed.append(unit.path)
            limitations.extend(unit.path + ": " + reason for reason in result.limitations)
            for item in result.observations:
                if item.kind != "candidate":
                    continue
                findings.append(DetectorFinding(
                    file=unit.path, line=item.line, rule_id=RULE_ID,
                    message="Candidate only: CallStub result reaches ReplaceHirWithValue without the modeled pending-exception propagation helper.",
                    evidence_type="syntax", symbol=item.symbol, source_sha256=unit.sha256,
                    rule_version=VERSION, rule_lineage_id=RULE_ID,
                    evidence_obligations=tuple(EvidenceObligation(kind, description) for kind, description in (
                        ("call_semantics", "Verify CallStub may set a pending exception and this result path requires propagation."),
                        ("state_depend_semantics", "Verify GetState/GetDepend propagation requirements in the exact product build."),
                        ("control_flow", "Prove the result and replacement are reachable on the relevant generated control path."),
                        ("security_impact", "Establish a reachable attacker-controlled entry and concrete security impact."),
                        ("isolated_validation", "Reproduce the parent/fix behavior in an authorized isolated runtime/build."),
                    )),
                ))
        incomplete = any(state != "complete" for _, state in outcomes)
        limitations.append("Research-only exception rule; not registered in the product catalog.")
        return DetectorRun(self.detector_id, self.version, "blocked" if incomplete else "completed",
                           tuple(analyzed), tuple(findings), tuple(sorted(set(limitations))), tuple(outcomes))
