import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from src.core.scanner import scan_directory


REPO_ROOT = Path(__file__).resolve().parents[1]


class ScannerRegressionTests(unittest.TestCase):
    def test_positive_and_negative_samples_are_distinct_candidates(self) -> None:
        result = scan_directory(REPO_ROOT / "samples")

        self.assertEqual(result.scanned_files, 2)
        self.assertGreater(result.scanned_lines, 0)
        self.assertEqual(result.finding_count, 1)
        self.assertEqual(result.skipped_files, [])
        finding = result.findings[0]
        self.assertEqual(Path(finding.file_path).name, "demo_overflow.cpp")
        self.assertEqual(finding.rule_id, "cpp.dangerous_call.strcpy")
        self.assertEqual(finding.status, "candidate")
        self.assertEqual(finding.confidence, "unassessed")
        self.assertEqual(finding.severity, "unassessed")

    def test_call_shape_respects_identifier_boundary_and_whitespace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "example.cpp"
            source.write_text(
                "notstrcpy(dst, src);\nstrcpy (dst, src);\n",
                encoding="utf-8",
            )
            result = scan_directory(Path(directory))

        self.assertEqual(result.scanned_files, 1)
        self.assertEqual(result.scanned_lines, 2)
        self.assertEqual(result.finding_count, 1)
        self.assertEqual(result.findings[0].line, 2)

    def test_comment_and_string_literal_calls_are_not_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "example.c"
            source.write_text(
                "// strcpy(dst, src);\n"
                'char *fmt = "sprintf(buf, fmt);";\n'
                "/* memcpy(a, b, n); */\n"
                "strcpy(dst, src);\n",
                encoding="utf-8",
            )
            result = scan_directory(Path(directory))

        self.assertEqual(result.scanned_files, 1)
        self.assertEqual(result.scanned_lines, 4)
        self.assertEqual(result.finding_count, 1)
        self.assertEqual(result.findings[0].line, 4)
        self.assertEqual(result.findings[0].rule_id, "cpp.dangerous_call.strcpy")

    def test_inline_comment_after_real_call_keeps_single_match(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "example.c"
            source.write_text(
                "strcpy(dst, src); // strcpy(evil, x);\n",
                encoding="utf-8",
            )
            result = scan_directory(Path(directory))

        self.assertEqual(result.finding_count, 1)
        self.assertEqual(result.findings[0].line, 1)

    def test_cli_writes_consistent_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            json_output = Path(directory) / "report.json"
            md_output = Path(directory) / "report.md"
            process = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "src.cli",
                    "scan",
                    "samples",
                    "--json-out",
                    str(json_output),
                    "--md-out",
                    str(md_output),
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            data = json.loads(json_output.read_text(encoding="utf-8"))
            markdown = md_output.read_text(encoding="utf-8")

        self.assertEqual(data["scanned_files"], 2)
        self.assertEqual(data["finding_count"], len(data["findings"]))
        self.assertEqual(data["finding_count"], 1)
        self.assertEqual(data["findings"][0]["status"], "candidate")
        self.assertEqual(data["scope"]["include_paths"], ["."])
        self.assertEqual(data["scope"]["exclude_paths"], [])
        self.assertIn("Include scope: .", markdown)
        self.assertIn("Exclude scope: (none)", markdown)
        self.assertIn("Scanned files: 2", markdown)
        self.assertIn("Candidate findings: 1", markdown)
        self.assertIn("demo_overflow.cpp", markdown)
        self.assertNotIn("demo_safe_copy.cpp", markdown)
        self.assertIn("[OK] candidate findings: 1", process.stdout)

    def test_cli_rejects_missing_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            json_output = Path(directory) / "report.json"
            process = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "src.cli",
                    "scan",
                    str(Path(directory) / "missing"),
                    "--json-out",
                    str(json_output),
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(process.returncode, 0)
            self.assertIn("target is not a directory", process.stderr)
            self.assertFalse(json_output.exists())

    def test_include_scope_scans_only_requested_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            core = root / "core"
            tests_dir = root / "tests"
            core.mkdir()
            tests_dir.mkdir()
            (core / "keep.c").write_text("strcpy(dst, src);\n", encoding="utf-8")
            (tests_dir / "drop.c").write_text("strcpy(dst, src);\n", encoding="utf-8")

            result = scan_directory(root, include_paths=["core"])

        self.assertEqual(result.scope_includes, ["core"])
        self.assertEqual(result.scope_excludes, [])
        self.assertEqual(result.scanned_files, 1)
        self.assertEqual(result.finding_count, 1)
        self.assertEqual(Path(result.findings[0].file_path).name, "keep.c")

    def test_exclude_scope_prunes_requested_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            core = root / "core"
            tests_dir = root / "tests"
            core.mkdir()
            tests_dir.mkdir()
            (core / "keep.c").write_text("memcpy(dst, src, n);\n", encoding="utf-8")
            (tests_dir / "drop.c").write_text("strcpy(dst, src);\n", encoding="utf-8")

            result = scan_directory(root, exclude_paths=["tests"])

        self.assertEqual(result.scope_includes, ["."])
        self.assertEqual(result.scope_excludes, ["tests"])
        self.assertEqual(result.scanned_files, 1)
        self.assertEqual(result.finding_count, 1)
        self.assertEqual(Path(result.findings[0].file_path).name, "keep.c")

    def test_overlapping_include_paths_do_not_double_count_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            core = root / "core"
            core.mkdir()
            (core / "one.c").write_text("strcpy(dst, src);\n", encoding="utf-8")
            (root / "two.c").write_text("memcpy(dst, src, n);\n", encoding="utf-8")

            result = scan_directory(root, include_paths=[".", "core"])

        self.assertEqual(result.scanned_files, 2)
        self.assertEqual(result.finding_count, 2)

    def test_scope_path_cannot_escape_target_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "escapes target root"):
                scan_directory(root, include_paths=["../outside"])

    def test_cli_include_scope_is_recorded_in_reports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            json_output = Path(directory) / "report.json"
            md_output = Path(directory) / "report.md"
            process = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "src.cli",
                    "scan",
                    "samples",
                    "--include",
                    "vulnerable",
                    "--json-out",
                    str(json_output),
                    "--md-out",
                    str(md_output),
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            data = json.loads(json_output.read_text(encoding="utf-8"))
            markdown = md_output.read_text(encoding="utf-8")

        self.assertEqual(data["scope"]["include_paths"], ["vulnerable"])
        self.assertEqual(data["scope"]["exclude_paths"], [])
        self.assertEqual(data["scanned_files"], 1)
        self.assertEqual(data["finding_count"], 1)
        self.assertIn("Include scope: vulnerable", markdown)
        self.assertIn("[OK] include scope: vulnerable", process.stdout)


if __name__ == "__main__":
    unittest.main()
