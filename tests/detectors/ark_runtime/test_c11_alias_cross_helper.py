import hashlib
from pathlib import Path
import unittest

from src.ohscanner.detectors.ark_runtime.analysis import analyze_unit
from src.ohscanner.detectors.ark_runtime.exception_guard import analyze_exception_guard
from src.ohscanner.detectors.ark_runtime.receiver_guard import analyze_receiver_guard
from src.ohscanner.detectors.ark_runtime.runtime_exception import (
    analyze_native_inline_exception_propagation,
    analyze_runtime_exception_propagation,
)
from src.ohscanner.detectors.ark_runtime.size_overflow import (
    analyze_index_bounds_flows,
    analyze_length_narrowing_flows,
    analyze_size_overflow,
)
from .support import unit, wrap, PREFIX

FIXTURES = Path(__file__).parent / "fixtures" / "c11_alias_cross_helper"
GAP = Path(__file__).parent / "fixtures" / "c10_gap_rules"
SEM = Path(__file__).parent / "fixtures" / "c10_semantics"


def fixture(path):
    text = path.read_text(encoding="utf-8")
    source = unit(text, "tests/detectors/ark_runtime/fixtures/" + path.parent.name + "/" + path.name)
    assert source.sha256 == hashlib.sha256(text.encode("utf-8")).hexdigest()
    return source


def type_result(name):
    return analyze_unit(fixture(FIXTURES / name))


def type_kinds(result):
    return tuple(item.kind for item in result.observations)


class C11AliasCrossHelperControls(unittest.TestCase):
    def test_alias_cast_helper_and_loop_controls_are_fail_closed(self):
        for mechanism in ("alias", "cast", "helper"):
            with self.subTest(mechanism=mechanism):
                positive = type_result(mechanism + "_positive.cpp")
                self.assertIn("candidate", type_kinds(positive))
                self.assertFalse(any(kind in ("matched", "confirmed", "reportable")
                                     for kind in type_kinds(positive)))
                fixed = type_result(mechanism + "_fixed.cpp")
                self.assertIn("matched", type_kinds(fixed))
                self.assertNotIn("candidate", type_kinds(fixed))
                safe = type_result(mechanism + "_safe.cpp")
                self.assertIn("matched", type_kinds(safe))
                self.assertNotIn("candidate", type_kinds(safe))
                unrelated = type_result(mechanism + "_unrelated.cpp")
                self.assertFalse(type_kinds(unrelated))
                self.assertFalse(unrelated.observations)
                self.assertIn("not_applicable_to_rule", unrelated.limitations)
                unknown = type_result(mechanism + "_unknown.cpp")
                self.assertIn("unknown", type_kinds(unknown))
                self.assertFalse(any(kind in ("candidate", "matched") for kind in type_kinds(unknown)))

        positive, limitations = analyze_size_overflow(
            (FIXTURES / "loop_positive.cpp").read_text(encoding="utf-8"))
        self.assertEqual(len(positive), 1)
        self.assertEqual(positive[0].factor_names, ("stride", "count"))
        self.assertEqual(limitations, ())
        fixed, _ = analyze_size_overflow((FIXTURES / "loop_fixed.cpp").read_text(encoding="utf-8"))
        self.assertFalse(fixed)
        safe, _ = analyze_size_overflow((FIXTURES / "loop_safe.cpp").read_text(encoding="utf-8"))
        self.assertFalse(safe)
        unrelated, _ = analyze_size_overflow((FIXTURES / "loop_unrelated.cpp").read_text(encoding="utf-8"))
        self.assertFalse(unrelated)
        unknown_text = (FIXTURES / "loop_unknown.cpp").read_text(encoding="utf-8")
        macros = '#define RETURN_EXCEPTION_IF_ABRUPT_COMPLETION(thread) do { if ((thread)->HasPendingException()) { return JSTaggedValue::Exception(); } } while (false)\n'
        unknown = analyze_runtime_exception_propagation(
            unit(unknown_text, "ecmascript/builtins/builtins_typedarray.cpp"),
            source_units=(unit(macros, "ecmascript/ecma_macros.h"),))
        self.assertFalse(any(item.kind == "candidate" for item in unknown.observations))
        self.assertTrue(any("wrapper" in item for item in unknown.limitations))

    def test_unknown_wrapper_is_not_promoted_to_safe(self):
        text = (FIXTURES / "loop_unknown.cpp").read_text(encoding="utf-8")
        result = analyze_unit(unit(text))
        self.assertFalse(any(item.kind in ("candidate", "matched") for item in result.observations))

    def test_known_case_parent_or_explicit_unknown_and_fixed_controls_do_not_regress(self):
        for name in ("cve_2025_24304", "ibs5yg"):
            parent = analyze_unit(fixture(SEM / (name + "_parent.cpp")))
            fixed = analyze_unit(fixture(SEM / (name + "_fixed.cpp")))
            self.assertIn("candidate", type_kinds(parent))
            self.assertIn("matched", type_kinds(fixed))
            self.assertNotIn("candidate", type_kinds(fixed))

        size_parent = '''void convert(uint32_t stride, uint32_t count) {
    uint32_t byteCount = stride * count;
    auto temporary = AllocateArrayBuffer(byteCount);
    BufferHandle destination;
    destination.Update(temporary);
    for (uint32_t i = count; i > 0; --i) {
        SetValueInBuffer(thread, destination.GetTaggedValue(), cursor, value);
        cursor += stride;
    }
}
'''
        self.assertEqual(len(analyze_size_overflow(size_parent)[0]), 1)
        self.assertFalse(analyze_size_overflow(size_parent.replace(
            "uint32_t byteCount = stride * count",
            "uint64_t byteCount = static_cast<uint64_t>(stride) * count"))[0])

        exception_parent = unit(wrap(PREFIX + "GateRef klass = GetObjectType(LoadHClass(glue, output));"))
        exception_fixed = unit(wrap(PREFIX + (
            "Label exception(GetEnvironment()); Label normal(GetEnvironment()); Label exit(GetEnvironment());\n"
            "BRANCH(HasPendingException(glue), &exception, &normal);\n"
            "Bind(&exception); result->WriteVariable(Exception()); Jump(&exit);\n"
            "Bind(&normal); GateRef klass = GetObjectType(LoadHClass(glue, output)); Jump(&exit);\n"
            "Bind(&exit);")))
        self.assertEqual([item.kind for item in analyze_exception_guard(exception_parent).observations],
                         ["candidate"])
        self.assertNotIn("candidate", [item.kind for item in analyze_exception_guard(exception_fixed).observations])

        runtime_parent = '''class BuiltinsTypedArray {
JSTaggedValue Filter(EcmaRuntimeCallInfo *argv) {
    JSThread *thread = argv->GetThread();
    EcmaRuntimeCallInfo *info = EcmaInterpreter::NewRuntimeCallInfo(thread, callback, thisArg, undefined, 3);
    JSTaggedValue callbackOutcome = JSFunction::Call(info);
    bool accepted = callbackOutcome.ToBoolean();
    return accepted ? JSTaggedValue::True() : JSTaggedValue::False();
}
};
'''
        runtime_fixed = runtime_parent.replace(
            "    bool accepted = callbackOutcome.ToBoolean();",
            "    RETURN_EXCEPTION_IF_ABRUPT_COMPLETION(thread);\n    bool accepted = callbackOutcome.ToBoolean();")
        macros = '#define RETURN_EXCEPTION_IF_ABRUPT_COMPLETION(thread) do { if ((thread)->HasPendingException()) { return JSTaggedValue::Exception(); } } while (false)\n'
        self.assertEqual(len(analyze_runtime_exception_propagation(
            unit(runtime_parent, "ecmascript/builtins/builtins_typedarray.cpp"),
            source_units=(unit(macros, "ecmascript/ecma_macros.h"),)).observations), 1)
        self.assertFalse(analyze_runtime_exception_propagation(
            unit(runtime_fixed, "ecmascript/builtins/builtins_typedarray.cpp"),
            source_units=(unit(macros, "ecmascript/ecma_macros.h"),)).observations)

        ia_parent = (GAP / "ia_positive.cpp").read_text(encoding="utf-8")
        ia_fixed = (GAP / "ia_fixed.cpp").read_text(encoding="utf-8")
        self.assertEqual(analyze_native_inline_exception_propagation(unit(ia_parent)).observations[0].kind,
                         "candidate")
        self.assertFalse(analyze_native_inline_exception_propagation(unit(ia_fixed)).observations)

        self.assertEqual(len(analyze_length_narrowing_flows(
            (GAP / "length_positive.cpp").read_text(encoding="utf-8"))[0]), 1)
        self.assertFalse(analyze_length_narrowing_flows(
            (GAP / "length_fixed.cpp").read_text(encoding="utf-8"))[0])
        self.assertEqual(len(analyze_index_bounds_flows(
            (GAP / "index_positive.cpp").read_text(encoding="utf-8"))[0]), 1)
        self.assertFalse(analyze_index_bounds_flows(
            (GAP / "index_fixed.cpp").read_text(encoding="utf-8"))[0])

        receiver_parent = wrap(
            "Label exists(GetEnvironment()); Label typed(GetEnvironment());\n"
            "BRANCH(TaggedIsUndefinedOrNull(input), slowPath, &exists); Bind(&exists);\n"
            "GateRef buffer = GetViewedArrayBuffer(input);\n"
            "GateRef inputTag = GetObjectType(LoadHClass(input));\n"
            "BRANCH(IsFastTypeArray(inputTag), &typed, slowPath); Bind(&typed);")
        receiver_fixed = wrap(
            "Label exists(GetEnvironment()); Label typed(GetEnvironment());\n"
            "BRANCH(TaggedIsUndefinedOrNull(input), slowPath, &exists); Bind(&exists);\n"
            "GateRef inputTag = GetObjectType(LoadHClass(input));\n"
            "BRANCH(IsFastTypeArray(inputTag), &typed, slowPath); Bind(&typed);\n"
            "GateRef buffer = GetViewedArrayBuffer(input);")
        self.assertEqual([item.kind for item in analyze_receiver_guard(unit(receiver_parent)).observations],
                         ["candidate"])
        self.assertNotIn("candidate", [item.kind for item in analyze_receiver_guard(unit(receiver_fixed)).observations])


if __name__ == "__main__":
    unittest.main()
