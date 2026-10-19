import tempfile
import unittest
from pathlib import Path

from src.core.context import find_top_level_function_spans, resolve_context
from src.core.scanner import scan_directory


class FunctionContextTests(unittest.TestCase):
    def test_resolves_simple_top_level_c_function(self) -> None:
        lines = [
            "static void demo(const char *src)",
            "{",
            "    char dst[8];",
            "    strcpy(dst, src);",
            "}",
        ]

        context = resolve_context(lines, 4)

        self.assertEqual(context.function, "demo")
        self.assertEqual(context.function_start_line, 1)
        self.assertEqual(context.function_end_line, 5)
        self.assertEqual(context.context_start_line, 1)
        self.assertEqual(context.context_end_line, 5)
        self.assertEqual(context.status, "heuristic_top_level_function")
        self.assertIn("strcpy(dst, src);", context.snippet)

    def test_resolves_cjson_public_macro_style_signature(self) -> None:
        lines = [
            "CJSON_PUBLIC(char *) cJSON_Print(const cJSON *item)",
            "{",
            "    return print(item, true, &global_hooks);",
            "}",
        ]

        spans = find_top_level_function_spans(lines)

        self.assertEqual(len(spans), 1)
        self.assertEqual(spans[0].name, "cJSON_Print")
        self.assertEqual(spans[0].start_line, 1)
        self.assertEqual(spans[0].end_line, 4)

    def test_comment_and_string_braces_do_not_break_function_span(self) -> None:
        lines = [
            "static void demo(char *dst, const char *src)",
            "{",
            '    const char *text = "} not a real brace {";',
            "    /* } neither is this { */",
            "    strcpy(dst, src); // }",
            "}",
        ]

        context = resolve_context(lines, 5)

        self.assertEqual(context.function, "demo")
        self.assertEqual(context.function_start_line, 1)
        self.assertEqual(context.function_end_line, 6)

    def test_unresolved_top_level_candidate_still_has_local_context(self) -> None:
        lines = [
            "strcpy(dst, src);",
            "int value = 1;",
        ]

        context = resolve_context(lines, 1, radius=1)

        self.assertIsNone(context.function)
        self.assertIsNone(context.function_start_line)
        self.assertIsNone(context.function_end_line)
        self.assertEqual(context.status, "unresolved")
        self.assertEqual(context.context_start_line, 1)
        self.assertEqual(context.context_end_line, 2)
        self.assertIn("strcpy(dst, src);", context.snippet)

    def test_scanner_attaches_function_context_to_finding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "example.c"
            source.write_text(
                "static void demo(char *dst, const char *src)\n"
                "{\n"
                "    strcpy(dst, src);\n"
                "}\n",
                encoding="utf-8",
            )

            result = scan_directory(Path(directory))

        self.assertEqual(result.finding_count, 1)
        finding = result.findings[0]
        self.assertEqual(finding.function, "demo")
        self.assertEqual(finding.function_start_line, 1)
        self.assertEqual(finding.function_end_line, 4)
        self.assertEqual(finding.context_status, "heuristic_top_level_function")
        self.assertIn("strcpy(dst, src);", finding.context or "")


if __name__ == "__main__":
    unittest.main()
