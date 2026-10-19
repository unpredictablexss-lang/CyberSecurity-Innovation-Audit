import unittest

from src.parser.ast import parse_source


C_SAMPLE = """
static void demo(char *dst, const char *src) {
    char buf[8];
    strcpy(dst, src);
}

int helper(int n) { return n * 2; }
"""

CPP_SAMPLE = """
namespace OHOS {
int add(int a, int b) {
    return a + b;
}
void run() {
    std::string s;
    add(1, 2);
}
}
"""


class AstIndexTests(unittest.TestCase):
    def test_parses_c_function_definitions(self) -> None:
        index = parse_source(C_SAMPLE, language="c")
        names = [f.name for f in index.functions]
        self.assertIn("demo", names)
        self.assertIn("helper", names)

        demo = next(f for f in index.functions if f.name == "demo")
        self.assertEqual(demo.params, ["dst", "src"])
        self.assertEqual(demo.start_line, 2)
        self.assertEqual(demo.end_line, 5)

    def test_extracts_call_expressions_and_arguments(self) -> None:
        index = parse_source(C_SAMPLE, language="c")
        strcpy_calls = [c for c in index.calls if c.name == "strcpy"]
        self.assertEqual(len(strcpy_calls), 1)
        self.assertEqual(strcpy_calls[0].arguments, ["dst", "src"])
        self.assertEqual(strcpy_calls[0].line, 4)

    def test_extracts_variable_declarations(self) -> None:
        index = parse_source(C_SAMPLE, language="c")
        names = [v.name for v in index.variables]
        self.assertIn("buf", names)
        buf = next(v for v in index.variables if v.name == "buf")
        self.assertEqual(buf.type, "char")

    def test_parses_cpp_namespace_and_calls(self) -> None:
        index = parse_source(CPP_SAMPLE, language="cpp")
        func_names = [f.name for f in index.functions]
        self.assertIn("add", func_names)
        self.assertIn("run", func_names)
        add_calls = [c for c in index.calls if c.name == "add"]
        self.assertEqual(len(add_calls), 1)
        self.assertEqual(add_calls[0].arguments, ["1", "2"])

    def test_member_pointer_dispatch_is_normalized_without_losing_source_spans(self) -> None:
        code = """struct Stub {
    int dispatch() {
        return (this->*handler)(7);
    }
};
"""
        index = parse_source(code, language="cpp")
        self.assertEqual(index.parse_status, "complete")
        dispatch = next(function for function in index.functions if function.name == "dispatch")
        self.assertEqual(dispatch.start_line, 2)
        self.assertEqual(dispatch.end_line, 4)
        self.assertEqual(len(index.calls), 1)
        self.assertEqual(index.calls[0].line, 3)

    def test_rejects_unknown_language(self) -> None:
        with self.assertRaises(ValueError):
            parse_source("int x;", language="rust")


if __name__ == "__main__":
    unittest.main()
