from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
EXACT_SOURCES = ROOT / "research/experiments/ark-runtime-exact-source-20261018/sources"
sys.path.insert(0, str(ROOT))

from src.ohscanner.contracts import SourceUnit
from research.full_scan_20261018.lanes.c.analysis import analyze_unit
from research.full_scan_20261018.lanes.c.model import AnalysisBudget, OWNER, RuntimeTypeModel
from research.full_scan_20261018.lanes.c.syntax import parse_functions

TARGET = "ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp"


def load_unit(name: str) -> SourceUnit:
    data = (EXACT_SOURCES / name).read_bytes()
    text = data.decode("utf-8")
    return SourceUnit(TARGET, "cpp", text, hashlib.sha256(data).hexdigest(), "partial")


def run(unit: SourceUnit, caller: str | None = None):
    model = RuntimeTypeModel()
    if caller is None:
        model = replace(model, caller_profiles=())
    else:
        model = replace(model, caller=caller, caller_profiles=())
    return analyze_unit(unit, model=model, budget=AnalysisBudget(), research_partial=True)


class ExceptionSensitiveOriginTests(unittest.TestCase):
    def test_partial_source_never_becomes_a_public_complete_result(self):
        source = load_unit("type-origin-parent.cpp")
        before_status = source.parse_status
        research = run(source)
        production = analyze_unit(source, model=RuntimeTypeModel(), research_partial=False)
        self.assertEqual(source.parse_status, before_status)
        self.assertEqual(research.file_outcome, "partial")
        self.assertIn("parse_dependency_contamination_unknown", research.limitations)
        self.assertIn("production_runner_not_admitted", research.limitations)
        self.assertEqual(production.file_outcome, "not_analyzed")
        self.assertIn("production_requires_complete_ast", production.limitations)

    def test_species_result_alias_preserves_candidate_origin(self):
        source = load_unit("type-origin-parent.cpp")
        nl = "\r\n" if "\r\n" in source.text else "\n"
        creator = "GateRef newArray = newBuilder.NewTypedArray(glue, thisValue, arrayType, TruncInt64ToInt32(*newArrayLen));"
        store = "StoreTypedArrayElement(glue, newArray, ZExtInt32ToInt64(*i), kValue, arrayType);"
        text = source.text.replace(creator, creator + nl + "            GateRef aliasArray = newArray;", 1)
        text = text.replace(store, store.replace("newArray,", "aliasArray,"), 1)
        self.assertNotEqual(text, source.text)
        derived = SourceUnit(TARGET, "cpp", text, hashlib.sha256(text.encode()).hexdigest(), "partial")
        result = run(derived)
        filter_rows = [item for item in result.observations if item.symbol == OWNER + "::Filter"]
        self.assertEqual([(item.kind, item.reason) for item in filter_rows],
                         [("candidate", "different_origin_with_species_creation")])
        self.assertEqual(result.file_outcome, "partial")

    def test_generated_gate_reassignment_becomes_unknown(self):
        source = load_unit("type-origin-parent.cpp")
        nl = "\r\n" if "\r\n" in source.text else "\n"
        text = source.text.replace("            Bind(&notHasException2);",
                                   "            Bind(&notHasException2);" + nl + "            newArray = thisValue;", 1)
        self.assertNotEqual(text, source.text)
        derived = SourceUnit(TARGET, "cpp", text, hashlib.sha256(text.encode()).hexdigest(), "partial")
        result = run(derived)
        self.assertIn("unknown_observation:", "\n".join(result.limitations))
        self.assertTrue(any(item.symbol == OWNER + "::Filter" and item.kind == "unknown"
                            and item.reason == "host_rebinding_across_generated_blocks_unmodeled"
                            for item in result.observations))
        self.assertEqual(result.file_outcome, "partial")

    def test_nested_factory_call_does_not_preserve_creation_identity(self):
        source = load_unit("type-origin-parent.cpp")
        nl = "\r\n" if "\r\n" in source.text else "\n"
        creator = "GateRef newArray = newBuilder.NewTypedArray(glue, thisValue, arrayType, TruncInt64ToInt32(*newArrayLen));"
        wrapped = "GateRef newArray = WrapFactory(newBuilder.NewTypedArray(glue, thisValue, arrayType, TruncInt64ToInt32(*newArrayLen)));"
        text = source.text.replace(creator, wrapped, 1)
        self.assertNotEqual(text, source.text)
        derived = SourceUnit(TARGET, "cpp", text, hashlib.sha256(text.encode()).hexdigest(), "partial")
        result = run(derived)
        self.assertEqual(result.file_outcome, "partial")
        self.assertTrue(any(item.symbol == OWNER + "::Filter" and item.kind == "unknown"
                            for item in result.observations))
        self.assertNotIn("candidate", [item.kind for item in result.observations])

    def test_looped_creation_site_is_not_reused_as_stable_identity(self):
        source = load_unit("type-origin-parent.cpp")
        nl = "\r\n" if "\r\n" in source.text else "\n"
        creator = "GateRef newArray = newBuilder.NewTypedArray(glue, thisValue, arrayType, TruncInt64ToInt32(*newArrayLen));"
        looped = (
            "Label syntheticLoop(env);" + nl
            + "            LoopBegin(&syntheticLoop);" + nl
            + "            " + creator + nl
            + "            LoopEnd(&syntheticLoop);"
        )
        text = source.text.replace(creator, looped, 1)
        self.assertNotEqual(text, source.text)
        derived = SourceUnit(TARGET, "cpp", text, hashlib.sha256(text.encode()).hexdigest(), "partial")
        result = run(derived)
        self.assertEqual(result.file_outcome, "partial")
        self.assertTrue(any(item.kind == "unknown" and item.reason == "loop_allocation_identity_unmodeled"
                            for item in result.observations))

    def test_model_symbol_macro_redefinition_blocks_analysis(self):
        source = load_unit("type-origin-parent.cpp")
        text = "#define GetObjectType(x) ((x))\n" + source.text
        derived = SourceUnit(TARGET, "cpp", text, hashlib.sha256(text.encode()).hexdigest(), "partial")
        result = run(derived)
        self.assertEqual(result.file_outcome, "not_analyzed")
        self.assertIn("model_symbol_macro_redefined", result.limitations)

    def test_conditionally_compiled_target_is_not_treated_as_unconditional(self):
        source = load_unit("type-origin-parent.cpp")
        data = source.text.encode("utf-8")
        _tree, functions = parse_functions(data)
        target = next(fn for fn in functions if fn.qualified_name == OWNER + "::Filter")
        wrapped = (data[:target.node.start_byte] + b"#if defined(ENABLE_TYPEDARRAY_FILTER)\n"
                   + data[target.node.start_byte:target.node.end_byte] + b"\n#endif\n"
                   + data[target.node.end_byte:]).decode("utf-8")
        derived = SourceUnit(TARGET, "cpp", wrapped, hashlib.sha256(wrapped.encode()).hexdigest(), "partial")
        result = run(derived)
        self.assertEqual(result.file_outcome, "not_analyzed")
        self.assertIn("target_conditional_compilation_unresolved", result.limitations)

    def test_model_type_alias_shadowing_blocks_local_semantics(self):
        source = load_unit("type-origin-parent.cpp")
        text = "using GateRef = uintptr_t;\n" + source.text
        derived = SourceUnit(TARGET, "cpp", text, hashlib.sha256(text.encode()).hexdigest(), "partial")
        result = run(derived)
        self.assertEqual(result.file_outcome, "not_analyzed")
        self.assertIn("model_type_declaration_unverified", result.limitations)

    def test_derived_same_name_method_is_not_a_resolved_model_owner(self):
        text = """namespace panda::ecmascript::kungfu {
class BuiltinsTypedArrayStubBuilder {};
class DerivedBuilder : public BuiltinsTypedArrayStubBuilder {
public:
    void Filter(GateRef, GateRef, GateRef, Variable*, Label*, Label*);
};
void DerivedBuilder::Filter(GateRef a, GateRef b, GateRef c,
                            Variable* result, Label* exit, Label* slowPath)
{
    StoreTypedArrayElement(a, b, c, result, slowPath);
}
}
"""
        source = SourceUnit(TARGET, "cpp", text, hashlib.sha256(text.encode()).hexdigest(), "complete")
        result = analyze_unit(source, model=RuntimeTypeModel(), budget=AnalysisBudget())
        self.assertEqual(result.file_outcome, "complete")
        self.assertEqual(result.observations, ())
        self.assertIn("not_applicable_to_rule", result.limitations)

    def test_typedarray_method_matrix_is_explicitly_partial(self):
        expected = {
            "Filter": {
                "parent": ("candidate", "different_origin_with_species_creation"),
                "fix": ("unknown", "new_typed_array_type_read_before_exception_check"),
            },
            "CopyWithin": {
                "parent": ("unknown", "creation_relationship_invalidated_by_call"),
                "fix": ("unknown", "creation_relationship_invalidated_by_call"),
            },
            "Set": {
                "parent": ("matched", "target_origin_or_proved_type_equality"),
                "fix": ("matched", "target_origin_or_proved_type_equality"),
            },
            "With": {
                "parent": ("unknown", "unresolved_target_or_type_origin"),
                "fix": ("unknown", "unresolved_target_or_type_origin"),
            },
        }
        for revision in ("parent", "fix"):
            source = load_unit(f"type-origin-{revision}.cpp")
            for method, revisions in expected.items():
                with self.subTest(revision=revision, method=method):
                    result = run(source, OWNER + "::" + method)
                    kind, reason = revisions[revision]
                    self.assertEqual([(item.kind, item.reason) for item in result.observations],
                                     [(kind, reason)])
                    self.assertEqual(result.file_outcome, "partial")

    def test_parent_preserves_type_origin_candidate(self):
        result = run(load_unit("type-origin-parent.cpp"))
        self.assertEqual([item.kind for item in result.observations], ["candidate"])
        self.assertEqual(result.observations[0].reason, "different_origin_with_species_creation")
        self.assertEqual(result.file_outcome, "partial")

    def test_fixed_source_with_pre_guard_type_read_is_unknown(self):
        result = run(load_unit("type-origin-fix.cpp"))
        self.assertEqual([item.kind for item in result.observations], ["unknown"])
        self.assertEqual(result.observations[0].reason, "new_typed_array_type_read_before_exception_check")
        self.assertIn(
            f"unknown_observation:{result.observations[0].line}:new_typed_array_type_read_before_exception_check",
            result.limitations,
        )
        self.assertEqual(result.file_outcome, "partial")

    def test_post_guard_type_read_can_match(self):
        source = load_unit("type-origin-fix.cpp")
        nl = "\r\n" if "\r\n" in source.text else "\n"
        before = (
            "GateRef newArrayType = GetObjectType(LoadHClass(newArray));" + nl
            + "            BRANCH(HasPendingException(glue), &hasException2, &notHasException2);"
        )
        after = (
            "BRANCH(HasPendingException(glue), &hasException2, &notHasException2);"
        )
        guarded = source.text.replace(before, after, 1)
        self.assertNotEqual(guarded, source.text)
        guarded = guarded.replace(
            "            Bind(&notHasException2);" + nl + "            i = Int32(0);",
            "            Bind(&notHasException2);" + nl
            + "            GateRef newArrayType = GetObjectType(LoadHClass(newArray));" + nl
            + "            i = Int32(0);",
            1,
        )
        derived = SourceUnit(TARGET, "cpp", guarded,
                            hashlib.sha256(guarded.encode("utf-8")).hexdigest(), "partial")
        result = run(derived)
        self.assertEqual([item.kind for item in result.observations], ["matched"])
        self.assertEqual(result.file_outcome, "partial")

    def test_safe_and_unrelated_caller_controls_remain_stable(self):
        source = load_unit("type-origin-fix.cpp")
        safe = run(source, OWNER + "::Set")
        unrelated = run(source, OWNER + "::Map")
        self.assertEqual([item.kind for item in safe.observations], ["matched"])
        self.assertEqual(unrelated.observations, ())
        self.assertEqual(safe.file_outcome, "partial")
        self.assertEqual(unrelated.file_outcome, "partial")

    def test_unmodeled_call_after_guard_invalidates_exception_fact(self):
        source = load_unit("type-origin-fix.cpp")
        nl = "\r\n" if "\r\n" in source.text else "\n"
        guarded = source.text.replace(
            "            Bind(&notHasException2);" + nl + "            i = Int32(0);",
            "            Bind(&notHasException2);" + nl
            + "            GateRef unrelated = UnknownCall();" + nl
            + "            GateRef newArrayType = GetObjectType(LoadHClass(newArray));" + nl
            + "            i = Int32(0);",
            1,
        )
        guarded = guarded.replace(
            "GateRef newArrayType = GetObjectType(LoadHClass(newArray));" + nl
            + "            BRANCH(HasPendingException(glue), &hasException2, &notHasException2);",
            "BRANCH(HasPendingException(glue), &hasException2, &notHasException2);",
            1,
        )
        self.assertNotEqual(guarded, source.text)
        derived = SourceUnit(TARGET, "cpp", guarded,
                            hashlib.sha256(guarded.encode("utf-8")).hexdigest(), "partial")
        result = run(derived)
        self.assertNotEqual([item.kind for item in result.observations], ["matched"])
        self.assertIn("unresolved_local_observations", result.limitations)


if __name__ == "__main__":
    unittest.main()
