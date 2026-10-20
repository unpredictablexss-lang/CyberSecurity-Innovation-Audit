"""T87 independent empty split-C++-linkage recovery and raw-position controls."""
import hashlib
import unittest

from src.parser.ast import parse_source
from src.parser import syntax_normalize
from src.ohscanner.detectors.data.models import SensitiveSourceModel
from src.ohscanner.detectors.data.sensitive_exposure import LocalFlow
from src.ohscanner.frontend import index_sources
from src.ohscanner.git_source import GitSource
from src.ohscanner.contracts import SourceUnit

OPEN = '#ifdef __cplusplus\nextern "C" {\n#endif\n'
CLOSE = '#ifdef __cplusplus\n}\n#endif\n'
PROBE = 'int probe(){ return Sentinel(7); }\n'


def normalize(data):
    # Baseline identity fallback permits a meaningful red/green comparison.
    function = getattr(syntax_normalize, 'normalize_empty_cpp_linkage_wrappers', lambda value: value)
    return function(data)


class T87CppLinkageTests(unittest.TestCase):
    def check_call_positions(self, code, expected_status):
        data = code.encode()
        index = parse_source(code, 'cpp')
        self.assertEqual(expected_status, index.parse_status)
        call = next(call for call in index.calls if call.name == 'Sentinel')
        start = data.index(b'Sentinel(7)')
        self.assertEqual(start, call.start_byte)
        self.assertEqual(start + len(b'Sentinel(7)'), call.end_byte)
        self.assertEqual(data[:start].count(b'\n') + 1, call.line)
        self.assertEqual(['7'], call.arguments)
        self.assertEqual(b'Sentinel(7)', data[call.start_byte:call.end_byte])
        return index

    def test_exact_empty_pair_and_same_outer_context_recover(self):
        for code in (OPEN + CLOSE + PROBE,
                     '#ifdef FEATURE\n' + OPEN + '\n' + CLOSE + '#endif\n' + PROBE):
            with self.subTest(code=code):
                projected = normalize(code.encode())
                self.assertNotEqual(code.encode(), projected)
                self.check_call_positions(code, 'complete')

    def test_utf8_crlf_bytes_lines_and_original_source_are_preserved(self):
        code = ('// 中文 prefix\n' + OPEN + '\n\n' + CLOSE + PROBE).replace('\n', '\r\n')
        original = code.encode()
        projected = normalize(original)
        self.assertEqual(len(original), len(projected))
        self.assertEqual([i for i,b in enumerate(original) if b in (10, 13)],
                         [i for i,b in enumerate(projected) if b in (10, 13)])
        self.assertEqual(original[:original.index(b'#ifdef')], projected[:original.index(b'#ifdef')])
        self.check_call_positions(code, 'complete')
        blob = hashlib.sha1(b'blob ' + str(len(original)).encode() + b'\0' + original).hexdigest()
        units, ast, _ = index_sources((GitSource('guard.h', 'cpp', blob, original),))
        self.assertEqual('complete', units[0].parse_status)
        self.assertEqual(code, units[0].text)
        self.assertEqual(hashlib.sha256(original).hexdigest(), units[0].sha256)
        self.assertEqual('complete', ast['guard.h']['parse_status'])

    def test_shared_and_sensitive_private_ast_agree_on_recovery(self):
        code = OPEN + CLOSE + PROBE
        data = code.encode()
        unit = SourceUnit(path='guard.h', language='cpp', text=code,
                          sha256=hashlib.sha256(data).hexdigest(), parse_status='complete')
        flow = LocalFlow(unit, SensitiveSourceModel('fixture/t87', 'a' * 40))
        self.assertFalse(flow.tree.root_node.has_error)
        self.assertEqual(data, flow.b)
        self.assertEqual(len(data), flow.tree.root_node.end_byte)

    def test_unpaired_wrong_order_and_repeated_openings_remain_partial(self):
        cases = (OPEN + PROBE, CLOSE + PROBE, CLOSE + OPEN + PROBE,
                 OPEN + OPEN + CLOSE + PROBE)
        for code in cases:
            with self.subTest(code=code):
                self.assertEqual(code.encode(), normalize(code.encode()))
                self.check_call_positions(code, 'partial')

    def test_extra_closing_marker_never_becomes_complete(self):
        self.check_call_positions(OPEN + CLOSE + CLOSE + PROBE, 'partial')

    def test_real_declarations_and_alternate_branch_are_not_discarded(self):
        cases = (
            OPEN + 'int c_api(int);\n' + CLOSE + PROBE,
            OPEN.replace('#endif', '#else\nint fallback;\n#endif') + CLOSE + PROBE,
        )
        for code in cases:
            with self.subTest(code=code):
                self.assertEqual(code.encode(), normalize(code.encode()))
                self.check_call_positions(code, 'partial')

    def test_different_preprocessor_contexts_are_not_paired(self):
        code = ('#ifdef FEATURE_A\n' + OPEN + '#endif\n#ifdef FEATURE_B\n' + CLOSE + '#endif\n' + PROBE)
        self.assertEqual(code.encode(), normalize(code.encode()))
        self.check_call_positions(code, 'partial')

    def test_plain_extern_is_already_complete_and_unchanged(self):
        code = 'extern "C" { int c_api(int); }\n' + PROBE
        self.assertEqual(code.encode(), normalize(code.encode()))
        self.check_call_positions(code, 'complete')

    def test_comment_raw_string_and_macro_lookalikes_are_unchanged(self):
        pair = OPEN + CLOSE
        cases = (
            '/*\n' + pair + '*/\n' + PROBE,
            'const char *text=R"LINK(\n' + pair + ')LINK";\n' + PROBE,
            '#define LINKAGE_TEXT \\\n' + pair + PROBE,
        )
        for code in cases:
            with self.subTest(code=code):
                self.assertEqual(code.encode(), normalize(code.encode()))

    def test_function_class_and_namespace_embedded_pairs_are_unchanged(self):
        for prefix, suffix in (('void outer(){\n', '}\n'),
                               ('class X {\n', '};\n'),
                               ('namespace X {\n', '}\n')):
            code = prefix + OPEN + CLOSE + suffix + PROBE
            with self.subTest(prefix=prefix):
                self.assertEqual(code.encode(), normalize(code.encode()))

    def test_c_frontend_does_not_receive_cpp_projection(self):
        code = OPEN + CLOSE + PROBE
        self.assertEqual('partial', parse_source(code, 'c').parse_status)


if __name__ == '__main__':
    unittest.main()
