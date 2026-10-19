import json
import tempfile
import unittest
from pathlib import Path

from src.benchmark.scanner_compare import compare_text_and_ast
from src.core.ast_scanner import scan_directory_ast
from src.core.scanner import scan_directory


REPO_ROOT = Path(__file__).resolve().parents[1]


def _write_report(directory: Path, name: str, result) -> Path:
    path = directory / name
    path.write_text(json.dumps(result.to_dict()), encoding="utf-8")
    return path


class ScannerCompareTests(unittest.TestCase):
    def test_compare_reports_macro_difference(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "x.c").write_text(
                "#define COPY(d, s) strcpy((d), (s))\n"
                "void demo(char *a, char *b) { strcpy(a, b); }\n",
                encoding="utf-8",
            )
            text_json = _write_report(root, "text.json", scan_directory(root))
            ast_json = _write_report(root, "ast.json", scan_directory_ast(root))
            comparison = compare_text_and_ast(text_json, ast_json)

        self.assertEqual(comparison.text_count, 2)
        self.assertEqual(comparison.ast_count, 1)
        self.assertEqual(comparison.overlap_count, 1)
        self.assertEqual(len(comparison.text_only), 1)
        self.assertEqual(len(comparison.ast_only), 0)
        self.assertEqual(comparison.text_only[0].rule_id, "cpp.dangerous_call.strcpy")

    def test_compare_reports_identical_on_samples(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            text_json = _write_report(root, "text.json", scan_directory(REPO_ROOT / "samples"))
            ast_json = _write_report(root, "ast.json", scan_directory_ast(REPO_ROOT / "samples"))
            comparison = compare_text_and_ast(text_json, ast_json)

        self.assertEqual(comparison.text_count, 1)
        self.assertEqual(comparison.ast_count, 1)
        self.assertEqual(comparison.overlap_count, 1)
        self.assertEqual(len(comparison.text_only), 0)
        self.assertEqual(len(comparison.ast_only), 0)

    def test_compare_rejects_different_targets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            left = root / "left"
            right = root / "right"
            left.mkdir()
            right.mkdir()
            (left / "a.c").write_text("strcpy(a, b);\n", encoding="utf-8")
            (right / "a.c").write_text("strcpy(a, b);\n", encoding="utf-8")
            text_json = _write_report(root, "text.json", scan_directory(left))
            ast_json = _write_report(root, "ast.json", scan_directory_ast(right))
            with self.assertRaises(ValueError):
                compare_text_and_ast(text_json, ast_json)

    def test_interpretation_marks_differences_as_review_leads(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "x.c").write_text(
                "#define C strcpy((d), (s))\n"
                "void demo(char *a, char *b) { strcpy(a, b); }\n",
                encoding="utf-8",
            )
            text_json = _write_report(root, "text.json", scan_directory(root))
            ast_json = _write_report(root, "ast.json", scan_directory_ast(root))
            comparison = compare_text_and_ast(text_json, ast_json)

        data = comparison.to_dict()
        self.assertIn("text_only_candidates", data)
        self.assertIn("ast_only_candidates", data)
        self.assertIn("interpretation", data)


if __name__ == "__main__":
    unittest.main()
