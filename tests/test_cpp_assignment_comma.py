"""D102 same-span, common-syntax recovery; source and other errors stay intact."""
import unittest
import tree_sitter_cpp
from tree_sitter import Language, Parser
from src.parser.ast import parse_source
from src.parser.cpp_assignment_comma import recover_cpp_assignment_commas


def nodes(node):
    yield node
    for child in node.named_children:
        yield from nodes(child)


class AssignmentCommaRecoveryTests(unittest.TestCase):
    def recover(self, source):
        data = source.encode('utf-8')
        raw = Parser(Language(tree_sitter_cpp.language())).parse(data)
        return data, raw, recover_cpp_assignment_commas(data, raw)

    def test_exact_span_and_precedence(self):
        data, raw, tree = self.recover('void f(){ const char*out; const char*key; unsigned code=(out=key,0); }')
        self.assertTrue(raw.root_node.has_error)
        self.assertFalse(tree.root_node.has_error)
        comma = next(n for n in nodes(tree.root_node) if n.type == 'comma_expression')
        left = comma.child_by_field_name('left')
        self.assertEqual('assignment_expression', left.type)
        self.assertEqual(b'out=key', data[left.start_byte:left.end_byte])
        self.assertEqual(b'0', data[comma.child_by_field_name('right').start_byte:comma.child_by_field_name('right').end_byte])
        self.assertEqual(tree.recovery_spans[0]['start_byte'], data.index(b'(out=key,0)'))
        self.assertEqual(data, tree.root_node.text)
        self.assertEqual(left.parent.id, comma.id)

    def test_utf8_crlf_calls_and_single_argument(self):
        source = '// 中文\r\nvoid f(){const char*out;const char*key;Use((out=key,0));}\r\n'
        index = parse_source(source, 'cpp')
        self.assertEqual('complete', index.parse_status)
        call = index.calls[0]
        self.assertEqual(['(out=key,0)'], call.arguments)
        self.assertEqual(source.encode().index(b'Use('), call.start_byte)
        self.assertEqual(b'Use((out=key,0))', source.encode()[call.start_byte:call.end_byte])
        self.assertEqual(2, call.line)
        self.assertEqual('recovered_cpp_assignment_comma', index.parse_issues[0]['kind'])

    def test_other_error_remains_partial(self):
        _, _, tree = self.recover('void f(){a=(b=c,0);} void broken( {')
        self.assertTrue(tree.root_node.has_error)
        self.assertEqual(1, len(tree.recovery_spans))

    def test_invalid_and_cpp_only_do_not_graft(self):
        for expression in ('(a=b,,0)', '(a=,0)', '(a=b /* keep */,0)',
                           '(a=Pick<0>(key),0)', '(a=operator,(e,0),0)',
                           '(a=typeid(key).name(),0)', '(a=[](){return 0;}(),0)'):
            with self.subTest(expression=expression):
                _, raw, tree = self.recover('void f(){unsigned result='+expression+';}')
                self.assertIs(tree, raw)
                self.assertTrue(tree.root_node.has_error)

    def test_existing_complete_tree_identity(self):
        for source in ('void f(){a=b,0;}', 'void f(){a=((b=c),0);}',
                       'void f(){Use(a,b);}', 'void f(){const char*s="(a=b,0)";}'):
            _, raw, tree = self.recover(source)
            self.assertFalse(raw.root_node.has_error)
            self.assertIs(raw, tree)

    def test_cpp_context_stays_cpp(self):
        source='namespace N{template<class T> T f(T x){return x;}} struct Tag{}; void g(){a=(b=c,0);}'
        _, _, tree=self.recover(source)
        self.assertFalse(tree.root_node.has_error)
        kinds={n.type for n in nodes(tree.root_node)}
        self.assertTrue({'namespace_definition','template_declaration','struct_specifier'} <= kinds)

    def test_c_language_uses_original_parser(self):
        index=parse_source('void f(){unsigned a,b,c; a=(b=c,0);}', 'c')
        self.assertEqual('complete', index.parse_status)
        self.assertEqual([], index.parse_issues)


if __name__ == '__main__':
    unittest.main()
