import json
import tempfile
import unittest
from pathlib import Path

from src.benchmark.compare import (
    compare_normalized_reports,
    load_normalized_report,
    write_reports,
)


def report(tool, diagnostics, *, commit="abc123", files=2, loc=100):
    return {
        "schema_version": 1,
        "run_id": f"run-{tool}",
        "tool": tool,
        "tool_version": "1.0",
        "target_id": "fixture-target",
        "commit": commit,
        "scope_files": files,
        "scope_loc": loc,
        "status": "completed",
        "elapsed_seconds": 1.0,
        "peak_memory_mb": 32.0,
        "diagnostic_count": len(diagnostics),
        "diagnostics": diagnostics,
        "limitations": [],
    }


def diagnostic(provider, evidence_type, file, line, suffix):
    return {
        "diagnostic_id": f"{provider}-{suffix}",
        "provider": provider,
        "evidence_type": evidence_type,
        "file": file,
        "line": line,
        "column": 1,
        "rule_id": f"rule-{suffix}",
        "severity": "warning",
        "message": "fixture",
        "candidate_cwe": None,
        "confidence": "unassessed",
    }


class MultiToolComparisonTests(unittest.TestCase):
    def _write(self, directory, name, data):
        path = Path(directory) / name
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_compare_reports_counts_overlap_descriptively(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            semgrep = self._write(
                directory,
                "semgrep.json",
                report(
                    "semgrep",
                    [
                        diagnostic("semgrep", "pattern", "a.c", 10, "1"),
                        diagnostic("semgrep", "pattern", "b.c", 20, "2"),
                    ],
                ),
            )
            clang = self._write(
                directory,
                "clang.json",
                report(
                    "clang_sa",
                    [
                        diagnostic("clang_sa", "symbolic", "a.c", 10, "1"),
                        diagnostic("clang_sa", "symbolic", "c.c", 30, "2"),
                    ],
                ),
            )
            result = compare_normalized_reports([semgrep, clang])

        self.assertEqual(result.target_id, "fixture-target")
        self.assertEqual(len(result.summaries), 2)
        overlap = result.pairwise_overlaps[0]
        self.assertEqual(overlap.exact_location_overlap, 1)
        self.assertEqual(overlap.left_only_locations, 1)
        self.assertEqual(overlap.right_only_locations, 1)

    def test_rejects_mismatched_commit_or_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            left = self._write(directory, "left.json", report("semgrep", []))
            right = self._write(
                directory,
                "right.json",
                report("codeql", [], commit="different"),
            )
            with self.assertRaisesRegex(ValueError, "not directly comparable"):
                compare_normalized_reports([left, right])

    def test_rejects_incomplete_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            data = report("cppcheck", [])
            data["status"] = "blocked"
            path = self._write(directory, "blocked.json", data)
            with self.assertRaisesRegex(ValueError, "not completed"):
                load_normalized_report(path)

    def test_writes_json_and_markdown_without_verdict_language(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            left = self._write(directory, "left.json", report("semgrep", []))
            right = self._write(directory, "right.json", report("codeql", []))
            result = compare_normalized_reports([left, right])
            json_output = Path(directory) / "comparison.json"
            md_output = Path(directory) / "comparison.md"
            write_reports(result, json_output, md_output)

            data = json.loads(json_output.read_text(encoding="utf-8"))
            markdown = md_output.read_text(encoding="utf-8")

        self.assertIn("not a vulnerability vote", data["interpretation"])
        self.assertIn("Descriptive comparison only", markdown)
        self.assertIn("No Precision/Recall", markdown)


if __name__ == "__main__":
    unittest.main()
