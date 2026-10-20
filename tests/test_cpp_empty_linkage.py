"""D88 exact empty-linkage recovery controls for the shared C++ parser."""
import unittest
from src.parser.ast import parse_source
from src.parser.syntax_normalize import normalize_empty_cpp_linkage_wrappers as normalize

OPEN = '#ifdef __cplusplus\nextern "C" {\n#endif\n'
CLOSE = '#ifdef __cplusplus\n}\n#endif\n'
CALL = 'void probe(){ SensitiveSink(7); }\n'


class EmptyCppLinkageTests(unittest.TestCase):
    def test_empty_pair_recovery_preserves_directives_and_call_offsets(self):
        code = ('// UTF-8 文本\n' + OPEN + '\n' + CLOSE + CALL).replace('\n', '\r\n')
        data = code.encode()
        normalized = normalize(data)
        self.assertEqual(len(normalized), len(data))
        self.assertEqual([i for i, b in enumerate(data) if b in (10, 13)],
                         [i for i, b in enumerate(normalized) if b in (10, 13)])
        self.assertEqual(normalized.count(b'#ifdef __cplusplus'), 2)
        self.assertEqual(normalized.count(b'#endif'), 2)
        index = parse_source(code, 'cpp')
        self.assertEqual(index.parse_status, 'complete')
        call = next(c for c in index.calls if c.name == 'SensitiveSink')
        self.assertEqual(data[call.start_byte:call.end_byte], b'SensitiveSink(7)')
        self.assertEqual(call.start_byte, data.index(b'SensitiveSink(7)'))

    def test_no_general_preprocessing_or_declaration_removal(self):
        for code in (OPEN + 'int api(int);\n' + CLOSE + CALL,
                     OPEN + CALL, CLOSE + CALL, CLOSE + OPEN + CALL,
                     '#ifdef A\n' + OPEN + '#endif\n#ifdef B\n' + CLOSE + '#endif\n' + CALL):
            with self.subTest(code=code):
                self.assertEqual(normalize(code.encode()), code.encode())
                self.assertEqual(parse_source(code, 'cpp').parse_status, 'partial')

    def test_lexical_and_non_global_lookalikes_are_unchanged(self):
        for code in ('/*\n' + OPEN + CLOSE + '*/\n',
                     'const char *text=R"x(\n' + OPEN + CLOSE + ')x";\n',
                     'void outer(){\n' + OPEN + CLOSE + '}\n',
                     'class X{\n' + OPEN + CLOSE + '};\n',
                     'namespace X{\n' + OPEN + CLOSE + '}\n'):
            with self.subTest(code=code):
                self.assertEqual(normalize(code.encode()), code.encode())

    def test_multiple_exact_pairs_are_idempotent_and_do_not_hide_other_errors(self):
        code = OPEN + CLOSE + OPEN + CLOSE + CALL
        once = normalize(code.encode())
        self.assertEqual(normalize(once), once)
        self.assertEqual(parse_source(code, 'cpp').parse_status, 'complete')
        self.assertEqual(parse_source(OPEN + CLOSE + CLOSE + CALL, 'cpp').parse_status, 'partial')

    def test_c_language_stays_unmodified_and_partial(self):
        self.assertEqual(parse_source(OPEN + CLOSE + CALL, 'c').parse_status, 'partial')


if __name__ == '__main__':
    unittest.main()
