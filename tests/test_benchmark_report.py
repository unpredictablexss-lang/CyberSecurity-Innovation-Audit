import unittest
from pathlib import Path

from src.benchmark.historical import load_sample
from src.benchmark.root_cause_matrix import ToolCandidate
from src.report.benchmark_report import build_benchmark_report, render_markdown


REPO_ROOT = Path(__file__).resolve().parents[1]


def _samples():
    return [
        load_sample(path)
        for path in sorted((REPO_ROOT / "benchmarks" / "historical").glob("*.json"))
    ]


class BenchmarkReportTests(unittest.TestCase):
    def test_build_report_with_bundled_samples(self) -> None:
        samples = _samples()
        self.assertEqual(len(samples), 7)
        report = build_benchmark_report(
            samples,
            {
                "own_text": [],
                "own_ast": [],
                "semgrep": None,
                "codeql": None,
                "clang_sa": None,
                "cppcheck": None,
            },
        )
        self.assertEqual(report.sample_count, 7)
        self.assertEqual(
            set(report.root_cause_group_distribution),
            {
                "lifetime_uaf", "concurrency_race", "null_deref", "oob_write",
                "integer_overflow", "type_confusion", "permission_bypass",
            },
        )
        self.assertEqual(
            set(report.cwe_distribution),
            {"CWE-416", "CWE-125", "CWE-476", "CWE-787", "CWE-190", "CWE-843", "CWE-284"},
        )
        self.assertEqual(report.validated_vulnerability, 0)

    def test_runtime_validation_all_not_run(self) -> None:
        report = build_benchmark_report(
            _samples(),
            {"own_text": [], "own_ast": [], "semgrep": None},
        )
        self.assertEqual(set(report.runtime_validation_by_sample.values()), {"not_run"})

    def test_report_title_is_benchmark_summary(self) -> None:
        report = build_benchmark_report(
            _samples(),
            {"own_text": [], "own_ast": [], "semgrep": None},
        )
        self.assertEqual(report.to_dict()["title"], "Historical Benchmark Summary Report")

    def test_markdown_heading_is_not_vulnerability_report(self) -> None:
        report = build_benchmark_report(
            _samples(),
            {"own_text": [], "own_ast": [], "semgrep": None},
        )
        md = render_markdown(report)
        self.assertIn("# Historical Benchmark Summary Report", md)
        self.assertNotIn("# Vulnerability Report", md)
        self.assertIn("validated_vulnerability = 0", md)

    def test_own_text_and_ast_are_miss_for_current_samples(self) -> None:
        report = build_benchmark_report(
            _samples(),
            {
                "own_text": [],
                "own_ast": [],
                "semgrep": None,
                "codeql": None,
                "clang_sa": None,
                "cppcheck": None,
            },
        )
        matrix = report.root_cause_matrix
        for row in matrix.rows:
            if row.tool in {"own_text", "own_ast"}:
                self.assertEqual(row.status, "miss")
            else:
                self.assertEqual(row.status, "unknown")


if __name__ == "__main__":
    unittest.main()
