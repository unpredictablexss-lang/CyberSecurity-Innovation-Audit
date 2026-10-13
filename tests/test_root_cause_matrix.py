import unittest
from pathlib import Path

from src.benchmark.historical import HistoricalSample, load_sample
from src.benchmark.root_cause_matrix import (
    NOT_APPLICABLE,
    RootCauseMatrix,
    ToolCandidate,
    build_root_cause_hit_matrix,
    classify_tool_hit,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


def _sample(affected_files=None, affected_symbols=None, group="null_deref") -> HistoricalSample:
    return HistoricalSample(
        schema_version=1,
        sample_id="s",
        title="t",
        repository="r",
        repo_url="https://x",
        vulnerable_commit="a",
        fixed_commit="b",
        weakness="CWE-476",
        affected_files=affected_files or ["f.c"],
        affected_symbols=affected_symbols or ["fn"],
        root_cause="rc",
        source_refs=["https://ref"],
        root_cause_group=group,
    )


class RootCauseMatrixTests(unittest.TestCase):
    def test_possible_hit_when_file_and_symbol_match(self) -> None:
        sample = _sample(affected_files=["a/b.c"], affected_symbols=["fn"])
        hit = classify_tool_hit(
            sample, "own_text", [ToolCandidate(file="a/b.c", symbol="fn", line=10)]
        )
        self.assertEqual(hit.status, "possible_hit")
        self.assertEqual(hit.evidence_count, 1)

    def test_miss_when_symbol_does_not_match(self) -> None:
        sample = _sample(affected_files=["a/b.c"], affected_symbols=["fn"])
        hit = classify_tool_hit(
            sample, "own_text", [ToolCandidate(file="a/b.c", symbol="other")]
        )
        self.assertEqual(hit.status, "miss")
        self.assertEqual(hit.evidence_count, 0)

    def test_miss_when_file_does_not_match(self) -> None:
        sample = _sample(affected_files=["a/b.c"], affected_symbols=["fn"])
        hit = classify_tool_hit(
            sample, "own_text", [ToolCandidate(file="x/y.c", symbol="fn")]
        )
        self.assertEqual(hit.status, "miss")

    def test_unknown_when_tool_not_run(self) -> None:
        sample = _sample()
        hit = classify_tool_hit(sample, "semgrep", None)
        self.assertEqual(hit.status, "unknown")
        self.assertEqual(hit.evidence_count, 0)

    def test_not_applicable_is_distinct_from_unknown(self) -> None:
        sample = _sample()

        not_run = classify_tool_hit(sample, "codeql", None)
        cannot_apply = classify_tool_hit(sample, "codeql", NOT_APPLICABLE)

        self.assertEqual(not_run.status, "unknown")
        self.assertEqual(cannot_apply.status, "not_applicable")
        self.assertEqual(cannot_apply.evidence_count, 0)

    def test_not_applicable_survives_matrix_build(self) -> None:
        matrix = build_root_cause_hit_matrix(
            [_sample()],
            {"codeql": NOT_APPLICABLE, "clang_sa": None, "cppcheck": []},
        )
        by_tool = {row.tool: row.status for row in matrix.rows}
        self.assertEqual(by_tool["codeql"], "not_applicable")
        self.assertEqual(by_tool["clang_sa"], "unknown")
        self.assertEqual(by_tool["cppcheck"], "miss")

    def test_rejects_ambiguous_candidate_payload(self) -> None:
        with self.assertRaisesRegex(ValueError, "must be a list"):
            classify_tool_hit(_sample(), "codeql", "not_applicable")

    def test_markdown_renders_not_applicable(self) -> None:
        from src.benchmark.root_cause_matrix import render_markdown

        matrix = build_root_cause_hit_matrix(
            [_sample()], {"codeql": NOT_APPLICABLE}
        )
        text = render_markdown(matrix)
        self.assertIn("not_applicable", text)

    def test_matrix_builds_sample_x_tool_rows(self) -> None:
        samples = [_sample(group="g1"), _sample(group="g2")]
        tool_candidates = {
            "own_text": [],
            "own_ast": [],
            "semgrep": None,
            "codeql": None,
        }
        matrix = build_root_cause_hit_matrix(samples, tool_candidates)

        self.assertEqual(len(matrix.rows), 2 * 4)
        by_tool = {row.tool for row in matrix.rows}
        self.assertEqual(by_tool, {"own_text", "own_ast", "semgrep", "codeql"})

    def test_matrix_with_bundled_samples_all_text_miss(self) -> None:
        samples = [
            load_sample(path)
            for path in sorted((REPO_ROOT / "benchmarks" / "historical").glob("*.json"))
        ]
        self.assertEqual(len(samples), 7)
        tool_candidates = {
            "own_text": [],
            "own_ast": [],
            "clang": None,
            "semgrep": None,
            "codeql": None,
            "cppcheck": None,
        }
        matrix = build_root_cause_hit_matrix(samples, tool_candidates)
        groups = {row.root_cause_group for row in matrix.rows}
        self.assertGreaterEqual(len(groups), 4)
        for row in matrix.rows:
            if row.tool in {"own_text", "own_ast"}:
                self.assertEqual(row.status, "miss")
            else:
                self.assertEqual(row.status, "unknown")

    def test_never_uses_tp_fp_fn(self) -> None:
        matrix = build_root_cause_hit_matrix(
            [_sample()], {"own_text": [], "semgrep": None}
        )
        statuses = {row.status for row in matrix.rows}
        self.assertTrue(statuses <= {"possible_hit", "miss", "unknown", "not_applicable"})
        self.assertFalse(statuses & {"tp", "fp", "fn", "true_positive", "false_positive"})


if __name__ == "__main__":
    unittest.main()
