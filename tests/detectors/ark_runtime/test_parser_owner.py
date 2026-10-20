"""Fail-closed, source-bound Tree-sitter owner recovery controls."""
import unittest
import os
import subprocess
from hashlib import sha256
from pathlib import Path

from src.ohscanner.detectors.ark_runtime.syntax import parse_functions, walk
from src.ohscanner.detectors.ark_runtime.analysis import analyze_unit
from src.parser.ast import parse_source
from .support import unit


class ParserOwnerTests(unittest.TestCase):
    def assert_unresolved(self, fn, *limitations):
        self.assertIsNone(fn.owner_identity)
        self.assertEqual(fn.owner_source, "unknown")
        self.assertIn(fn.owner_status, {"unknown", "limitation"})
        self.assertEqual(fn.candidate_status, "candidate")
        self.assertEqual(fn.assessment_status, "unassessed")
        for limitation in limitations:
            self.assertIn(limitation, fn.owner_limitations)

    def test_positive_complete_visible_class_owner_is_source_bound(self):
        source = (
            b"namespace panda { namespace kungfu {\n"
            b"class Builder { public: void Filter(); };\n"
            b"void Builder::Filter(GateRef value) {}\n"
            b"} }\n"
        )
        tree, functions = parse_functions(source)
        self.assertFalse(tree.root_node.has_error)
        self.assertEqual(len(functions), 1)
        fn = functions[0]
        self.assertEqual(fn.function_name, "Filter")
        self.assertEqual(fn.written_declarator_name, "Builder::Filter")
        self.assertEqual(fn.qualified_name, "panda::kungfu::Builder::Filter")
        self.assertEqual(fn.owner_source, "ast")
        self.assertEqual(fn.owner_status, "resolved")
        self.assertEqual(fn.owner_identity.spelling, "panda::kungfu::Builder")
        self.assertEqual(fn.translation_unit_status, "complete")
        self.assertEqual(fn.external_context_status, "unknown")
        self.assertEqual(fn.candidate_status, "candidate")
        self.assertEqual(fn.assessment_status, "unassessed")
        self.assertEqual(fn.source_sha256,
                         sha256(source[fn.source_span[0]:fn.source_span[1]]).hexdigest())
        self.assertEqual(fn.owner_identity.components[-1].source_sha256,
                         sha256(b"Builder").hexdigest())

    def test_fixed_macro_shape_restores_only_visible_structural_owner(self):
        broken = (
            b"namespace panda { class Builder { public: void Broken(); "
            b"void Filter(); };\n"
            b"void Builder::Broken() { IR_IF (condition) { first(); } "
            b"IR_ELSE { second(); } }\n"
            b"void Builder::Filter() {}\n}\n"
        )
        fixed = (
            b"namespace panda { class Builder { public: void Broken(); "
            b"void Filter(); };\n"
            b"void Builder::Broken() { if (condition) { first(); } "
            b"else { second(); } }\n"
            b"void Builder::Filter() {}\n}\n"
        )
        broken_tree, broken_functions = parse_functions(broken)
        fixed_tree, fixed_functions = parse_functions(fixed)
        self.assertTrue(broken_tree.root_node.has_error)
        self.assertFalse(fixed_tree.root_node.has_error)
        broken_filter = next(fn for fn in broken_functions if fn.function_name == "Filter")
        fixed_filter = next(fn for fn in fixed_functions if fn.function_name == "Filter")
        self.assert_unresolved(broken_filter, "partial_parse")
        self.assertEqual(broken_filter.qualified_name, "Builder::Filter")
        self.assertEqual(fixed_filter.qualified_name, "panda::Builder::Filter")
        self.assertEqual(fixed_filter.owner_identity.spelling, "panda::Builder")

    def test_safe_control_is_candidate_unassessed_and_not_a_safety_verdict(self):
        source = b"void BenignHelper() { return; }\n"
        tree, functions = parse_functions(source)
        self.assertFalse(tree.root_node.has_error)
        fn = functions[0]
        self.assert_unresolved(fn, "missing_owner_token")
        self.assertEqual(fn.candidate_status, "candidate")
        self.assertEqual(fn.assessment_status, "unassessed")
        self.assertFalse(hasattr(fn, "verdict"))
        self.assertNotEqual(fn.owner_status, "safe")

    def test_unrelated_same_name_functions_keep_source_bound_owner_identities(self):
        source = (
            b"namespace panda { class Builder { public: void Filter(); }; "
            b"void Builder::Filter() {} "
            b"namespace other { class Builder { public: void Filter(); }; "
            b"void Builder::Filter() {} } }\n"
        )
        tree, functions = parse_functions(source)
        self.assertFalse(tree.root_node.has_error)
        self.assertEqual([fn.qualified_name for fn in functions], [
            "panda::Builder::Filter",
            "panda::other::Builder::Filter",
        ])
        self.assertNotEqual(functions[0].owner_identity, functions[1].owner_identity)
        self.assertEqual({fn.assessment_status for fn in functions}, {"unassessed"})

    def test_owner_and_signature_controls_do_not_collapse_to_name_only(self):
        source = (
            b"namespace panda::ecmascript::kungfu {\n"
            b"class BuiltinsTypedArrayStubBuilder { public: void Filter(GateRef); "
            b"void Filter(GateRef, GateRef); };\n"
            b"class OtherBuilder { public: void Filter(GateRef); };\n"
            b"void BuiltinsTypedArrayStubBuilder::Filter(GateRef value) {}\n"
            b"void BuiltinsTypedArrayStubBuilder::Filter(GateRef value, GateRef count) {}\n"
            b"void OtherBuilder::Filter(GateRef value) {}\n"
            b"}\n"
        )
        tree, functions = parse_functions(source)
        self.assertFalse(tree.root_node.has_error)
        self.assertEqual([fn.qualified_name for fn in functions], [
            "panda::ecmascript::kungfu::BuiltinsTypedArrayStubBuilder::Filter",
            "panda::ecmascript::kungfu::BuiltinsTypedArrayStubBuilder::Filter",
            "panda::ecmascript::kungfu::OtherBuilder::Filter",
        ])
        self.assertEqual([fn.parameter_types for fn in functions], [
            ["GateRef"], ["GateRef", "GateRef"], ["GateRef"],
        ])
        self.assertNotEqual(functions[0].owner_identity, functions[2].owner_identity)

        global_source = (
            b"class Builder { public: void Filter(GateRef); };\n"
            b"void Builder::Filter(GateRef value) {}\n"
        )
        _, global_functions = parse_functions(global_source)
        self.assertEqual(global_functions[0].qualified_name, "Builder::Filter")
        self.assertEqual(global_functions[0].owner_identity.spelling, "Builder")
        self.assertEqual(global_functions[0].parameter_types, ["GateRef"])

    def test_nested_namespaces_and_same_named_methods_keep_distinct_owners(self):
        source = (
            b"namespace panda { namespace ecmascript { namespace kungfu {\n"
            b"class Builder { public: void Filter(GateRef); };\n"
            b"void Builder::Filter(GateRef value) {}\n"
            b"namespace other { class Builder { public: void Filter(GateRef); }; "
            b"void Builder::Filter(GateRef value) {} }\n"
            b"} } }\n"
        )
        tree, functions = parse_functions(source)
        self.assertFalse(tree.root_node.has_error)
        self.assertEqual([fn.qualified_name for fn in functions], [
            "panda::ecmascript::kungfu::Builder::Filter",
            "panda::ecmascript::kungfu::other::Builder::Filter",
        ])
        self.assertTrue(all(fn.translation_unit_status == "complete" for fn in functions))
        self.assertTrue(all(fn.external_context_status == "unknown" for fn in functions))
        self.assertNotEqual(functions[0].owner_identity, functions[1].owner_identity)

    def test_unknown_cross_translation_unit_owner_is_not_name_guessed(self):
        source = (
            b"namespace panda { void Builder::Filter(GateRef value) {} }\n"
        )
        tree, functions = parse_functions(source)
        self.assertFalse(tree.root_node.has_error)
        fn = functions[0]
        self.assert_unresolved(fn, "owner_not_visible_in_translation_unit")
        self.assertEqual(fn.qualified_name, "panda::Builder::Filter")
        self.assertEqual(fn.written_declarator_name, "Builder::Filter")

    def test_unknown_ambiguous_qualifier_is_fail_closed(self):
        source = (
            b"namespace panda { namespace A {} class A {}; "
            b"void A::Filter() {} }\n"
        )
        tree, functions = parse_functions(source)
        self.assertFalse(tree.root_node.has_error)
        self.assert_unresolved(functions[0], "ambiguous_owner_qualifier")
        self.assertEqual(functions[0].qualified_name, "panda::A::Filter")

    def test_unknown_missing_owner_token_and_macro_expansion(self):
        anonymous = b"namespace { void Filter() {} }\n"
        _, anonymous_functions = parse_functions(anonymous)
        self.assert_unresolved(anonymous_functions[0], "missing_owner_token")

        macro = (
            b"#define Builder RealBuilder\n"
            b"class RealBuilder { public: void Filter(); };\n"
            b"void Builder::Filter() {}\n"
        )
        macro_tree, macro_functions = parse_functions(macro)
        self.assertFalse(macro_tree.root_node.has_error)
        self.assert_unresolved(macro_functions[0], "macro_owner_expansion_unknown")

    def test_missing_external_owner_include_is_fail_closed(self):
        fixture = (
            Path(__file__).parent
            / "fixtures"
            / "ark_runtime"
            / "parser_owner"
            / "missing_external_owner.cpp"
        )
        source = fixture.read_bytes()
        tree, functions = parse_functions(source)
        self.assertFalse(tree.root_node.has_error)
        self.assertEqual(len(functions), 1)
        self.assert_unresolved(functions[0], "owner_not_visible_in_translation_unit")
        self.assertEqual(functions[0].external_context_status, "unknown")
        self.assertEqual(functions[0].owner_status, "limitation")
        self.assertEqual(functions[0].qualified_name_status, "source_spelling_unverified")

    def test_partial_mixed_parse_error_regression_stays_unknown(self):
        source = (
            b"namespace panda {\n"
            b"void Clean() {}\n"
            b"void Builder::Broken() { IR_IF (condition) { first(); } "
            b"IR_ELSE { second(); } }\n"
            b"void Builder::Filter(GateRef value) {}\n"
            b"}\n"
        )
        tree, functions = parse_functions(source)
        self.assertTrue(tree.root_node.has_error)
        self.assertEqual(len(functions), 3)
        self.assertEqual([fn.function_name for fn in functions], ["Clean", "Broken", "Filter"])
        for fn in functions:
            self.assert_unresolved(fn, "partial_parse", "parse_error_or_missing_token")
            self.assertEqual(fn.translation_unit_status, "partial")
            self.assertEqual(fn.qualified_name_status, "source_spelling_unverified")
            self.assertEqual(fn.external_context_status, "unknown")
        self.assertEqual([fn.qualified_name for fn in functions],
                         ["panda::Clean", "panda::Builder::Broken", "Builder::Filter"])
        self.assertEqual(functions[2].written_declarator_name, "Builder::Filter")

    def test_missing_macro_and_type_declarations_remain_unknown_on_partial_file(self):
        source = (
            b"namespace panda::ecmascript::kungfu {\n"
            b"void Builder::Broken() { IR_IF (condition) { DEFVARIABLE(x); } "
            b"IR_ELSE { missing(x); } }\n"
            b"void Builder::Filter(GateRef value, Label *exit) {}\n"
            b"}\n"
        )
        tree, functions = parse_functions(source)
        self.assertTrue(tree.root_node.has_error)
        self.assertEqual(parse_source(source.decode(), "cpp").parse_status, "partial")
        filter_fn = next(fn for fn in functions if fn.function_name == "Filter")
        self.assert_unresolved(filter_fn, "partial_parse", "parse_error_or_missing_token")
        self.assertEqual(filter_fn.translation_unit_status, "partial")
        self.assertEqual(filter_fn.external_context_status, "unknown")
        result = analyze_unit(unit(source.decode()), research_partial=True)
        self.assertNotEqual(result.file_outcome, "complete")
        self.assertFalse(result.observations)
        self.assertIn("target_not_resolved_in_partial_ast", result.limitations)

    def test_truncated_namespace_disables_owner_recovery(self):
        source = (
            b"namespace panda::ecmascript::kungfu {\n"
            b"void Builder::Filter(GateRef value) { BRANCH(test, &a, &b);\n"
        )
        tree, functions = parse_functions(source)
        self.assertTrue(tree.root_node.has_error)
        self.assertEqual(functions, [])

    def test_bound_typedarray_target_stays_partial_and_unknown(self):
        root = os.environ.get("OHSCANNER_ARK_REPO")
        if not root:
            self.skipTest("OHSCANNER_ARK_REPO not configured")
        repo = Path(root)
        relative = "ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp"
        target = repo / relative
        if not target.is_file():
            local_source = b"void Builder::Filter(GateRef value) {}\n"
            tree, functions = parse_functions(local_source)
            self.assertFalse(tree.root_node.has_error)
            self.assertEqual(len(functions), 1)
            self.assert_unresolved(
                functions[0], "owner_not_visible_in_translation_unit"
            )
            self.assertEqual(functions[0].external_context_status, "unknown")
            self.assertEqual(
                functions[0].qualified_name_status, "source_spelling_unverified"
            )
            return
        source = target.read_bytes()
        revision = subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
        ).strip()
        self.assertEqual(revision, "a65a2853ccae13da167d9aa4720ab8b11ec16656")
        self.assertEqual(subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", "HEAD:" + relative], text=True
        ).strip(), "68fb3b0adc4f9062889a861be51b7be90362e37a")
        self.assertEqual(sha256(source).hexdigest(),
                         "76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c")
        tree, functions = parse_functions(source)
        self.assertTrue(tree.root_node.has_error)
        self.assertEqual(parse_source(source.decode(), "cpp").parse_status, "partial")
        targets = [fn for fn in functions if fn.function_name in {"Filter", "Map"}]
        self.assertEqual({fn.function_name for fn in targets}, {"Filter", "Map"})
        for fn in targets:
            self.assert_unresolved(fn, "partial_parse", "parse_error_or_missing_token")
            self.assertEqual(fn.translation_unit_status, "partial")
            self.assertEqual(fn.external_context_status, "unknown")
            self.assertTrue(fn.written_declarator_name.endswith("::" + fn.function_name))


if __name__ == "__main__":
    unittest.main()
