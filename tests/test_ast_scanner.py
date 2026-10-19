import tempfile
import unittest
from pathlib import Path

from src.core.ast_scanner import scan_directory_ast


REPO_ROOT = Path(__file__).resolve().parents[1]


class AstScannerTests(unittest.TestCase):
    def test_finds_dangerous_call_in_vulnerable_sample(self) -> None:
        result = scan_directory_ast(REPO_ROOT / "samples")

        self.assertEqual(result.engine, "ast")
        self.assertEqual(result.scanned_files, 2)
        self.assertEqual(result.finding_count, 1)
        finding = result.findings[0]
        self.assertEqual(Path(finding.file_path).name, "demo_overflow.cpp")
        self.assertEqual(finding.rule_id, "cpp.dangerous_call.strcpy")
        self.assertEqual(finding.function, "bad_copy")
        self.assertEqual(finding.context_status, "ast_function_context")

    def test_ignores_comment_and_string_literal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "example.c"
            source.write_text(
                "// strcpy(dst, src);\n"
                'char *fmt = "sprintf(buf, fmt);";\n'
                "/* memcpy(a, b, n); */\n"
                "void demo() { strcpy(dst, src); }\n",
                encoding="utf-8",
            )
            result = scan_directory_ast(Path(directory))

        self.assertEqual(result.finding_count, 1)
        self.assertEqual(result.findings[0].line, 4)
        self.assertEqual(result.findings[0].rule_id, "cpp.dangerous_call.strcpy")

    def test_extracts_call_arguments_as_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "example.c"
            source.write_text(
                "void demo(char *dst, const char *src) { memcpy(dst, src, n); }\n",
                encoding="utf-8",
            )
            result = scan_directory_ast(Path(directory))

        self.assertEqual(result.finding_count, 1)
        finding = result.findings[0]
        self.assertEqual(finding.rule_id, "cpp.dangerous_call.memcpy")
        self.assertIn("memcpy(dst, src, n)", finding.evidence)
        self.assertEqual(finding.function, "demo")

    def test_keeps_candidate_not_validated_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "example.c"
            source.write_text(
                "void d(char *a, char *b) { strcpy(a, b); }\n", encoding="utf-8"
            )
            result = scan_directory_ast(Path(directory))

        finding = result.findings[0]
        self.assertEqual(finding.status, "candidate")
        self.assertEqual(finding.confidence, "unassessed")
        self.assertEqual(finding.severity, "unassessed")

    def test_scope_include_prunes_other_directories(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "core").mkdir()
            (root / "tests").mkdir()
            (root / "core" / "keep.c").write_text("strcpy(a, b);\n", encoding="utf-8")
            (root / "tests" / "drop.c").write_text("strcpy(a, b);\n", encoding="utf-8")

            result = scan_directory_ast(root, include_paths=["core"])

        self.assertEqual(result.scanned_files, 1)
        self.assertEqual(result.finding_count, 1)
        self.assertEqual(Path(result.findings[0].file_path).name, "keep.c")


if __name__ == "__main__":
    unittest.main()
