"""Tree-sitter owner recovery controls for malformed C++ namespace scopes."""
import unittest

from src.ohscanner.detectors.ark_runtime.syntax import parse_functions, walk
from src.ohscanner.detectors.ark_runtime.analysis import analyze_unit
from .support import unit


class ParserOwnerTests(unittest.TestCase):
    def test_custom_ir_else_error_drops_namespace_for_following_definition(self):
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
        # The error is the unmatched namespace brace; the recovered namespace
        # node ends before it and the later method becomes a root child.
        self.assertEqual(source[errors[0].start_byte:errors[0].end_byte], b"}")
        self.assertEqual(errors[0].parent.type, "translation_unit")
        self.assertEqual(broken.node.parent.type, "declaration_list")
        self.assertEqual(filter_fn.node.parent.type, "translation_unit")
        self.assertEqual(filter_fn.qualified_name,
                         "BuiltinsTypedArrayStubBuilder::Filter")
        self.assertNotEqual(filter_fn.qualified_name,
                            "panda::ecmascript::kungfu::BuiltinsTypedArrayStubBuilder::Filter")
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

    def test_partial_tree_keeps_unscoped_typedarray_helper_unverified(self):
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
                         "BuiltinsTypedArrayStubBuilder::FastGetPropertyByIndex")
        self.assertEqual(helper.parameter_types,
                         ["GateRef", "GateRef", "GateRef", "GateRef"])

        result = analyze_unit(unit(source), research_partial=True)
        self.assertEqual(result.file_outcome, "not_analyzed")
        self.assertEqual(result.limitations,
                         ("visible_origin_operation_unverified",))


if __name__ == "__main__":
    unittest.main()
