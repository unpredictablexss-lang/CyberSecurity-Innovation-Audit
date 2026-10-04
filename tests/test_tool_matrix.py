import json
import tempfile
import unittest
from pathlib import Path

from src.benchmark.tool_matrix import build_tool_matrix
from src.benchmark.tool_result import ToolDiagnostic, ToolRunResult


def _run(tool: str, target_id: str, cwes, evidence_types, seconds: float) -> ToolRunResult:
    diagnostics = [
        ToolDiagnostic(
            diagnostic_id=f"{tool}:{i}",
            provider=tool,
            evidence_type=evidence_types[i % len(evidence_types)],
            file="x.c",
            line=i + 1,
            column=1,
            rule_id=f"rule-{i}",
            severity="warning",
            message="msg",
            candidate_cwe=cwes[i % len(cwes)],
        )
        for i in range(len(cwes))
    ]
    return ToolRunResult(
        schema_version=1,
        run_id=f"{tool}-run",
        tool=tool,
        tool_version="1.0",
        target_id=target_id,
        commit="abc",
        scope_files=1,
        scope_loc=100,
        status="completed",
        elapsed_seconds=seconds,
        peak_memory_mb=50.0,
        diagnostics=diagnostics,
    )


class ToolMatrixTests(unittest.TestCase):
    def test_build_matrix_summarizes_tools(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            semgrep = _run("semgrep", "t1", ["CWE-120", "CWE-787"], ["pattern"], 1.0)
            codeql = _run("codeql", "t1", ["CWE-120"], ["dataflow"], 2.5)
            (root / "s.json").write_text(json.dumps(semgrep.to_dict()), encoding="utf-8")
            (root / "c.json").write_text(json.dumps(codeql.to_dict()), encoding="utf-8")

            matrix = build_tool_matrix([root / "s.json", root / "c.json"])

        self.assertEqual(matrix.target_id, "t1")
        by_tool = {row.tool: row for row in matrix.rows}
        self.assertEqual(by_tool["semgrep"].diagnostic_count, 2)
        self.assertEqual(by_tool["semgrep"].cwe_count, 2)
        self.assertEqual(by_tool["codeql"].diagnostic_count, 1)
        self.assertEqual(by_tool["codeql"].cwe_count, 1)
        self.assertEqual(by_tool["semgrep"].evidence_types, {"pattern": 2})
        self.assertEqual(by_tool["codeql"].peak_memory_mb, 50.0)

    def test_build_matrix_rejects_different_targets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            a = _run("semgrep", "t1", ["CWE-120"], ["pattern"], 1.0)
            b = _run("codeql", "t2", ["CWE-120"], ["dataflow"], 1.0)
            (root / "a.json").write_text(json.dumps(a.to_dict()), encoding="utf-8")
            (root / "b.json").write_text(json.dumps(b.to_dict()), encoding="utf-8")
            with self.assertRaises(ValueError):
                build_tool_matrix([root / "a.json", root / "b.json"])

    def test_matrix_does_not_compute_precision_or_recall(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            a = _run("semgrep", "t1", ["CWE-120"], ["pattern"], 1.0)
            (root / "a.json").write_text(json.dumps(a.to_dict()), encoding="utf-8")
            matrix = build_tool_matrix([root / "a.json"])

        data = matrix.to_dict()
        self.assertNotIn("precision", data)
        self.assertNotIn("recall", data)
        self.assertNotIn("f1", data)


if __name__ == "__main__":
    unittest.main()
