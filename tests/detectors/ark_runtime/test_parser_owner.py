"""Tree-sitter owner recovery controls for malformed C++ namespace scopes."""
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
    def test_custom_ir_else_error_recovers_owner_for_following_definition(self):
        # IR_ELSE is a project macro construct. The C++ grammar treats the
        # token after a compound statement as invalid and error-recovers by
        # ending the namespace before the following method definition.
        source = (
            b"namespace panda::ecmascript::kungfu {\n"
            b"void BuiltinsTypedArrayStubBuilder::Broken() {\n"
            b"  IR_IF (condition) { first(); } IR_ELSE { second(); }\n"
            b"}\n"
            b"void BuiltinsTypedArrayStubBuilder::Filter(GateRef glue, "
            b"GateRef value, GateRef count, Variable *result, Label *exit, "
            b"Label *slowPath) {}\n"
            b"}\n"
        )
        tree, functions = parse_functions(source)
        broken = next(fn for fn in functions if fn.qualified_name.endswith("::Broken"))
        filter_fn = next(fn for fn in functions if fn.qualified_name.endswith("::Filter"))

        self.assertTrue(tree.root_node.has_error)
        errors = [node for node in walk(tree.root_node) if node.type == "ERROR"]
        self.assertEqual(len(errors), 1)
        # Tree-sitter's error recovery loses the namespace node, while the
        # independent lexical scope scan retains the balanced source owner.
        self.assertEqual(source[errors[0].start_byte:errors[0].end_byte], b"}")
        self.assertEqual(errors[0].parent.type, "translation_unit")
        self.assertEqual(broken.node.parent.type, "declaration_list")
        self.assertEqual(filter_fn.node.parent.type, "translation_unit")
        self.assertEqual(filter_fn.qualified_name,
                         "panda::ecmascript::kungfu::BuiltinsTypedArrayStubBuilder::Filter")
        self.assertEqual(filter_fn.owner_source, "lexical_scope")
        self.assertEqual(filter_fn.translation_unit_status, "partial")
        self.assertEqual(filter_fn.external_context_status, "unknown")
        self.assertEqual(filter_fn.parameter_types,
                         ["GateRef", "GateRef", "GateRef", "Variable*", "Label*", "Label*"])
        # Positions remain byte-based and source-line based after recovery.
        self.assertEqual(filter_fn.node.start_point.row, 4)
        self.assertEqual(source[filter_fn.node.start_byte:filter_fn.node.end_byte],
                         b"void BuiltinsTypedArrayStubBuilder::Filter(GateRef glue, "
                         b"GateRef value, GateRef count, Variable *result, Label *exit, "
                         b"Label *slowPath) {}")

    def test_complete_namespace_and_class_method_have_distinct_structural_owners(self):
        source = (
            b"namespace panda::ecmascript::kungfu {\n"
            b"class BuiltinsTypedArrayStubBuilder { public: void Filter(GateRef); };\n"
            b"void BuiltinsTypedArrayStubBuilder::Filter(GateRef value) {}\n"
            b"}\n"
        )
        tree, functions = parse_functions(source)
        self.assertFalse(tree.root_node.has_error)
        self.assertEqual(parse_source(source.decode(), "cpp").parse_status, "complete")
        fn = functions[0]
        self.assertEqual(fn.node.parent.type, "declaration_list")
        self.assertEqual(fn.qualified_name,
                         "panda::ecmascript::kungfu::BuiltinsTypedArrayStubBuilder::Filter")
        namespace = fn.node.parent.parent
        self.assertEqual(namespace.type, "namespace_definition")
        self.assertEqual(namespace.child_by_field_name("name").text,
                         b"panda::ecmascript::kungfu")
        class_node = next(node for node in walk(tree.root_node)
                          if node.type == "class_specifier")
        self.assertEqual(class_node.parent.type, "declaration_list")
        self.assertEqual(class_node.child_by_field_name("name").text,
                         b"BuiltinsTypedArrayStubBuilder")
        member_decl = next(node for node in walk(class_node)
                           if node.type == "function_declarator")
        self.assertEqual(member_decl.parent.type, "field_declaration")

    def test_owner_and_signature_controls_do_not_collapse_to_name_only(self):
        source = (
            b"namespace panda::ecmascript::kungfu {\n"
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
        # A missing namespace and a changed signature stay distinguishable
        # even when owner and function spellings are otherwise identical.
        missing_namespace = b"void BuiltinsTypedArrayStubBuilder::Filter(GateRef value) {}"
        _, unscoped = parse_functions(missing_namespace)
        self.assertEqual(unscoped[0].qualified_name,
                         "BuiltinsTypedArrayStubBuilder::Filter")
        self.assertEqual(unscoped[0].parameter_types, ["GateRef"])

    def test_partial_tree_recovers_owner_but_keeps_dependencies_unknown(self):
        source = (
            "namespace panda::ecmascript::kungfu {\n"
            "void BuiltinsTypedArrayStubBuilder::Filter(GateRef glue, GateRef thisValue, "
            "GateRef numArgs, Variable *result, Label *exit, Label *slowPath) {}\n"
            "void BuiltinsTypedArrayStubBuilder::Broken() { "
            "IR_IF (condition) { first(); } IR_ELSE { second(); } }\n"
            "GateRef BuiltinsTypedArrayStubBuilder::FastGetPropertyByIndex("
            "GateRef glue, GateRef array, GateRef index, GateRef jsType) { return index; }\n"
            "}\n"
        )
        tree, functions = parse_functions(source.encode())
        self.assertTrue(tree.root_node.has_error)
        helper = next(fn for fn in functions
                      if "FastGetPropertyByIndex" in fn.qualified_name)
        self.assertEqual(helper.node.parent.type, "translation_unit")
        self.assertEqual(helper.qualified_name,
                         "panda::ecmascript::kungfu::BuiltinsTypedArrayStubBuilder::FastGetPropertyByIndex")
        self.assertEqual(helper.owner_source, "lexical_scope")
        self.assertEqual(helper.external_context_status, "unknown")
        self.assertEqual(helper.parameter_types,
                         ["GateRef", "GateRef", "GateRef", "GateRef"])

        result = analyze_unit(unit(source), research_partial=True)
        self.assertEqual(result.file_outcome, "partial")
        self.assertFalse(result.observations)
        self.assertIn("parse_dependency_contamination_unknown", result.limitations)
        self.assertIn("partial_scope_routed_through_semantic_selector", result.limitations)
        self.assertNotIn("experimental_partial_scope_routed_through_exact_binding_adapter",
                         result.limitations)

    def test_nested_namespaces_and_same_named_methods_keep_distinct_owners(self):
        source = (
            b"namespace panda { namespace ecmascript { namespace kungfu {\n"
            b"void Builder::Filter(GateRef value) {}\n"
            b"namespace other { void Builder::Filter(GateRef value) {} }\n"
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

    def test_missing_macro_and_type_declarations_remain_unknown_on_partial_file(self):
        # No definitions for IR_IF, IR_ELSE, GateRef, Label, or DEFVARIABLE are
        # in this source. A lexical owner does not supply those dependencies.
        source = (
            b"namespace panda::ecmascript::kungfu {\n"
            b"void Builder::Broken() { IR_IF (condition) { DEFVARIABLE(x); } "
            b"IR_ELSE { missing(x); } }\n"
            b"void Builder::Filter(GateRef value, Label *exit) {}\n"
            b"}\n"
        )
        tree, functions = parse_functions(source)
        filter_fn = next(fn for fn in functions if fn.qualified_name.endswith("::Filter"))
        self.assertTrue(tree.root_node.has_error)
        self.assertEqual(parse_source(source.decode(), "cpp").parse_status, "partial")
        self.assertEqual(filter_fn.owner_source, "lexical_scope")
        self.assertEqual(filter_fn.translation_unit_status, "partial")
        self.assertEqual(filter_fn.external_context_status, "unknown")
        self.assertFalse(filter_fn.node.has_error)
        result = analyze_unit(unit(source.decode()), research_partial=True)
        self.assertNotEqual(result.file_outcome, "complete")
        self.assertFalse(result.observations)

    def test_truncated_namespace_disables_lexical_owner_recovery(self):
        source = (
            b"namespace panda::ecmascript::kungfu {\n"
            b"void Builder::Filter(GateRef value) { BRANCH(test, &a, &b);\n"
        )
        tree, functions = parse_functions(source)
        self.assertTrue(tree.root_node.has_error)
        self.assertEqual(functions, [])

    def test_bound_typedarray_target_stays_partial_but_recovers_lexical_owner(self):
        root = os.environ.get("OHSCANNER_ARK_REPO")
        if not root:
            self.skipTest("OHSCANNER_ARK_REPO not configured")
        repo = Path(root)
        relative = "ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp"
        source = (repo / relative).read_bytes()
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
        self.assertEqual(len([node for node in walk(tree.root_node) if node.type == "ERROR"]), 6)
        targets = [fn for fn in functions if fn.qualified_name in {
            "panda::ecmascript::kungfu::BuiltinsTypedArrayStubBuilder::Filter",
            "panda::ecmascript::kungfu::BuiltinsTypedArrayStubBuilder::Map",
        }]
        self.assertEqual({fn.qualified_name.rsplit("::", 1)[-1] for fn in targets}, {"Filter", "Map"})
        self.assertTrue(all(fn.owner_source == "lexical_scope" for fn in targets))
        self.assertTrue(all(not fn.node.has_error for fn in targets))
        self.assertTrue(all(fn.translation_unit_status == "partial" for fn in targets))
        self.assertTrue(all(fn.external_context_status == "unknown" for fn in targets))


if __name__ == "__main__":
    unittest.main()
