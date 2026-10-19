"""Independent controls for the Reflect.apply pending-exception rule.

These are source-shape controls, not product vulnerability verdicts. The
normalized fixture preserves the caller/helper/value and Branch/replacement
relationships found in the pinned upstream source pair.
"""
from dataclasses import replace
from hashlib import sha1
import unittest

from src.ohscanner.contracts import ScanContext, ScanRequest
from src.ohscanner.detectors.ark_runtime.detector import ArkRuntimeTypeSafetyDetector
from src.ohscanner.detectors.ark_runtime.model import (
    AnalysisBudget, NATIVE_EXCEPTION_RULE_ID, RuntimeTypeModel,
)
from src.ohscanner.fixture import snapshot_digest
from src.parser.ast import parse_source
from .support import unit


NS = "panda::ecmascript::kungfu"
SHORT_OWNER = "NativeInlineLowering"
PATH = "ecmascript/compiler/native_inline_lowering.cpp"
REVISION = "3fc1d0b960e0b1bb5bfe1aad8066bb8c9aa99724"


def source(caller=None, helper=None, namespace=NS, owner="NativeInlineLowering",
           parse_status=None, include_helper=True):
    caller = caller or (
        "void {owner}::TryInlineReflectApply(GateRef gate, size_t argc, "
        "BuiltinsStubCSigns::ID id, bool skipThis) {{\n"
        "  GateRef ret = builder_.BuildControlDependOp(circuit_->ReflectApply(), "
        "{{target, thisValue, argumentsList}});\n"
        "  ReplaceGateWithPendingException(gate, ret);\n"
        "}}"
    ).format(owner=owner)
    helper = helper or (
        "void {owner}::ReplaceGateWithPendingException(GateRef hirGate, "
        "GateRef value) {{\n"
        "  GateRef state = builder_.GetState();\n"
        "  GateRef exceptionVal = builder_.ExceptionConstant();\n"
        "  GateRef equal = builder_.Equal(value, exceptionVal);\n"
        "  auto ifBranch = builder_.Branch(state, equal, 1, BranchWeight::DEOPT_WEIGHT);\n"
        "  GateRef ifTrue = builder_.IfTrue(ifBranch);\n"
        "  GateRef ifFalse = builder_.IfFalse(ifBranch);\n"
        "  StateDepend success(ifFalse, builder_.DependRelay(ifFalse, depend));\n"
        "  StateDepend exception(ifTrue, builder_.DependRelay(ifTrue, depend));\n"
        "  acc_.ReplaceHirWithIfBranch(hirGate, success, exception, value);\n"
        "}}"
    ).format(owner=owner)
    text = "namespace " + namespace + " {\n" + caller + "\n"
    if include_helper:
        text += helper + "\n"
    text += "}\n"
    parsed = unit(text, PATH)
    parse_status = parse_status or parsed.parse_status
    return replace(parsed, parse_status=parse_status,
                   parse_issues=("truncated translation unit",) if parse_status == "partial" else ())


def result(source_unit):
    from src.ohscanner.detectors.ark_runtime.runtime_exception import (
        analyze_native_inline_exception_propagation,
    )
    return analyze_native_inline_exception_propagation(source_unit)


def has_candidate(run):
    return any(item.kind == "candidate" for item in run.observations)


class NativeInlineExactRuleTests(unittest.TestCase):
    def test_parent_binds_reflect_apply_result_to_value_and_replacement_path(self):
        sample = source()
        self.assertEqual(sample.parse_status, "complete")
        run = result(sample)
        self.assertTrue(has_candidate(run))
        self.assertEqual(run.file_outcome, "partial")
        self.assertIn("sentinel", run.observations[0].reason)

    def test_fixed_pending_state_condition_is_a_control(self):
        fixed = source(helper=(
            "void {owner}::ReplaceGateWithPendingException(GateRef hirGate, GateRef value) {{\n"
            "  GateRef condition = builder_.HasPendingException(glue_);\n"
            "  auto ifBranch = builder_.Branch(builder_.GetState(), condition, 1);\n"
            "  GateRef ifTrue = builder_.IfTrue(ifBranch); GateRef ifFalse = builder_.IfFalse(ifBranch);\n"
            "  StateDepend success(ifFalse, builder_.DependRelay(ifFalse, depend));\n"
            "  StateDepend exception(ifTrue, builder_.DependRelay(ifTrue, depend));\n"
            "  acc_.ReplaceHirWithIfBranch(hirGate, success, exception, value);\n"
            "}}"
        ).format(owner=SHORT_OWNER))
        run = result(fixed)
        self.assertFalse(has_candidate(run))
        self.assertIn("fixed_pending_exception_check_control_not_security_verdict", run.limitations)

    def test_unrelated_has_pending_exception_does_not_mask_sentinel_candidate(self):
        helper = (
            "void {owner}::ReplaceGateWithPendingException(GateRef hirGate, GateRef value) {{\n"
            "  builder_.HasPendingException(unrelatedGlue);\n"
            "  GateRef exceptionVal = builder_.ExceptionConstant();\n"
            "  GateRef equal = builder_.Equal(value, exceptionVal);\n"
            "  auto ifBranch = builder_.Branch(builder_.GetState(), equal, 1);\n"
            "  acc_.ReplaceHirWithIfBranch(hirGate, success, exception, value);\n"
            "}}"
        ).format(owner=SHORT_OWNER)
        self.assertTrue(has_candidate(result(source(helper=helper))))

    def test_wrong_namespace_and_wrong_class_are_not_applicable(self):
        for ns, owner in (("other::namespace", "NativeInlineLowering"),
                          (NS, "UnrelatedLowering")):
            with self.subTest(namespace=ns, owner=owner):
                run = result(source(namespace=ns, owner=owner))
                self.assertFalse(has_candidate(run))
                self.assertNotEqual(run.file_outcome, "complete")

    def test_wrong_method_signature_is_unknown_not_a_candidate(self):
        caller = (
            "void {owner}::TryInlineReflectApply(GateRef gate, int wrongArity) {{\n"
            "  GateRef ret = builder_.BuildControlDependOp(circuit_->ReflectApply(), args);\n"
            "  ReplaceGateWithPendingException(gate, ret);\n"
            "}}"
        ).format(owner=SHORT_OWNER)
        run = result(source(caller=caller))
        self.assertFalse(has_candidate(run))
        self.assertNotEqual(run.file_outcome, "complete")

    def test_caller_helper_value_mismatch_is_not_a_candidate(self):
        caller = (
            "void {owner}::TryInlineReflectApply(GateRef gate, size_t argc, "
            "BuiltinsStubCSigns::ID id, bool skipThis) {{\n"
            "  GateRef ret = builder_.BuildControlDependOp(circuit_->ReflectApply(), args);\n"
            "  ReplaceGateWithPendingException(gate, unrelatedValue);\n"
            "}}"
        ).format(owner=SHORT_OWNER)
        run = result(source(caller=caller))
        self.assertFalse(has_candidate(run))

    def test_reassignment_between_reflect_apply_and_helper_is_unknown(self):
        caller = (
            "void {owner}::TryInlineReflectApply(GateRef gate, size_t argc, "
            "BuiltinsStubCSigns::ID id, bool skipThis) {{\n"
            "  GateRef ret = builder_.BuildControlDependOp(circuit_->ReflectApply(), args);\n"
            "  ret = unrelatedValue;\n"
            "  ReplaceGateWithPendingException(gate, ret);\n"
            "}}"
        ).format(owner=SHORT_OWNER)
        self.assertFalse(has_candidate(result(source(caller=caller))))

    def test_decoy_sentinel_comparison_and_branch_without_replacement_are_unknown(self):
        cases = (
            source(helper=("void {owner}::ReplaceGateWithPendingException(GateRef h, GateRef value) {{\n"
                          "  GateRef equal = builder_.Equal(unrelated, builder_.ExceptionConstant());\n"
                          "  auto ifBranch = builder_.Branch(state, equal, 1);\n"
                          "  acc_.ReplaceHirWithIfBranch(h, success, exception, value);\n"
                          "}}").format(owner=SHORT_OWNER)),
            source(helper=("void {owner}::ReplaceGateWithPendingException(GateRef h, GateRef value) {{\n"
                          "  GateRef equal = builder_.Equal(value, builder_.ExceptionConstant());\n"
                          "  auto ifBranch = builder_.Branch(state, equal, 1);\n"
                          "}}").format(owner=SHORT_OWNER)),
            source(helper=("void {owner}::ReplaceGateWithPendingException(GateRef h, GateRef value) {{\n"
                          "  GateRef equal = builder_.Equal(value, builder_.ExceptionConstant());\n"
                          "  auto ifBranch = builder_.Branch(state, equal, 1);\n"
                          "  GateRef decoyBranch = builder_.Branch(state, otherCondition, 1);\n"
                          "  GateRef ifTrue = builder_.IfTrue(decoyBranch);\n"
                          "  GateRef ifFalse = builder_.IfFalse(decoyBranch);\n"
                          "  StateDepend success(ifFalse, builder_.DependRelay(ifFalse, depend));\n"
                          "  StateDepend exception(ifTrue, builder_.DependRelay(ifTrue, depend));\n"
                          "  acc_.ReplaceHirWithIfBranch(h, success, exception, value);\n"
                          "}}").format(owner=SHORT_OWNER)),
        )
        for sample in cases:
            with self.subTest(text=sample.text[-160:]):
                self.assertFalse(has_candidate(result(sample)))

    def test_unrelated_branch_condition_is_not_the_sentinel_guard(self):
        helper = (
            "void {owner}::ReplaceGateWithPendingException(GateRef h, GateRef value) {{\n"
            "  GateRef equal = builder_.Equal(value, builder_.ExceptionConstant());\n"
            "  auto ifBranch = builder_.Branch(state, unrelatedCondition, 1);\n"
            "  acc_.ReplaceHirWithIfBranch(h, success, exception, value);\n"
            "}}"
        ).format(owner=SHORT_OWNER)
        self.assertFalse(has_candidate(result(source(helper=helper))))

    def test_partial_parse_preserves_candidate_and_unknown_parse_obligation(self):
        sample = source(parse_status="partial")
        run = result(sample)
        self.assertTrue(has_candidate(run))
        self.assertNotEqual(run.file_outcome, "complete")

    def test_missing_helper_is_unknown_not_safe(self):
        caller = ("void {owner}::TryInlineReflectApply(GateRef gate, size_t argc, "
                  "BuiltinsStubCSigns::ID id, bool skipThis) {{\n"
                  "  GateRef ret = builder_.BuildControlDependOp(circuit_->ReflectApply(), args);\n"
                  "  ReplaceGateWithPendingException(gate, ret);\n"
                  "}}").format(owner=SHORT_OWNER)
        sample = source(caller=caller, include_helper=False)
        run = result(sample)
        self.assertFalse(has_candidate(run))
        self.assertNotEqual(run.file_outcome, "complete")
        self.assertTrue(run.limitations)

    def test_unavailable_parse_is_not_misreported_as_safe(self):
        run = result(source(parse_status="failed"))
        self.assertFalse(has_candidate(run))
        self.assertEqual(run.file_outcome, "not_analyzed")
        self.assertIn("source_parse_unavailable", run.limitations)

    def test_source_binding_identity_failures_do_not_run_the_rule(self):
        sample = source(parse_status="partial")
        raw = sample.text.encode("utf-8")
        blob = sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
        base = RuntimeTypeModel()
        model = replace(base, native_exception_bindings=((REVISION, PATH, blob, sample.sha256),))
        ast = parse_source(sample.text, "cpp").to_dict()
        ast["parse_status"] = sample.parse_status
        ctx = ScanContext(
            ScanRequest("native-exception", base.source_repository, REVISION,
                        snapshot_digest((sample,)), "current-component:" + base.source_repository,
                        profile_id="light-ast", provenance="git_object"),
            (sample,), {"ast": {PATH: ast}, "source_blob_oid": {PATH: blob}},
        )
        detector = ArkRuntimeTypeSafetyDetector(model=model)
        bound_result = detector.detect(ctx, (sample,))
        self.assertEqual(len(bound_result.findings), 1)
        obligation_map = {item.kind: item.status
                          for item in bound_result.findings[0].evidence_obligations}
        self.assertIn("parse_completeness_impact", obligation_map)
        self.assertTrue(all(status == "unknown" for status in obligation_map.values()))
        for bad_facts in ({"ast": {PATH: ast}},
                          {"ast": {PATH: ast}, "source_blob_oid": {PATH: "0" * 40}}):
            with self.subTest(facts=bad_facts):
                blocked = detector.detect(replace(ctx, shared_facts=bad_facts), (sample,))
                self.assertFalse(blocked.findings)
                self.assertNotEqual(blocked.status, "complete")
        wrong_revision = replace(ctx, request=replace(ctx.request, commit="a" * 40))
        not_bound = detector.detect(wrong_revision, (sample,))
        self.assertFalse(not_bound.findings)
        self.assertNotEqual(not_bound.status, "complete")
        wrong_profile = replace(ctx, request=replace(
            ctx.request, profile_id="m0-synthetic", provenance="fixture"))
        profile_rejected = detector.detect(wrong_profile, (sample,))
        self.assertFalse(profile_rejected.findings)
        self.assertNotEqual(profile_rejected.status, "complete")
        exhausted = ArkRuntimeTypeSafetyDetector(
            model=model, budget=AnalysisBudget(max_source_bytes=1))
        budget_result = exhausted.detect(ctx, (sample,))
        self.assertFalse(budget_result.findings)
        self.assertNotEqual(budget_result.status, "complete")
        self.assertTrue(any("source_byte_budget_exhausted" in item
                            for item in budget_result.limitations))
        self.assertEqual(NATIVE_EXCEPTION_RULE_ID, "ark.runtime.native-inline-pending-exception-propagation")


if __name__ == "__main__":
    unittest.main()
