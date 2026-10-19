import unittest

from src.benchmark.tool_result import ToolDiagnostic, ToolRunResult


class ToolResultSchemaTests(unittest.TestCase):
    def test_serializes_descriptive_tool_run(self) -> None:
        diagnostic = ToolDiagnostic(
            diagnostic_id="semgrep:demo.c:10:rule-1",
            provider="semgrep",
            evidence_type="pattern",
            file="demo.c",
            line=10,
            column=3,
            rule_id="rule-1",
            severity="warning",
            message="candidate pattern",
            candidate_cwe="CWE-120",
        )
        result = ToolRunResult(
            schema_version=1,
            run_id="run-001",
            tool="semgrep",
            tool_version="1.x",
            target_id="fixture-target",
            commit="abc123",
            scope_files=2,
            scope_loc=100,
            status="completed",
            elapsed_seconds=0.5,
            peak_memory_mb=32.0,
            diagnostics=[diagnostic],
            limitations=["fixture only"],
        )

        data = result.to_dict()

        self.assertEqual(data["diagnostic_count"], 1)
        self.assertEqual(data["diagnostics"][0]["provider"], "semgrep")
        self.assertEqual(data["diagnostics"][0]["confidence"], "unassessed")
        self.assertIn("not validated vulnerabilities", data["interpretation"])

    def test_rejects_invalid_status(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported status"):
            ToolRunResult(
                schema_version=1,
                run_id="run-002",
                tool="cppcheck",
                tool_version="2.x",
                target_id="fixture-target",
                commit="abc123",
                scope_files=1,
                scope_loc=10,
                status="unknown-status",
                elapsed_seconds=0.1,
            )

    def test_rejects_invalid_evidence_type(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported evidence_type"):
            ToolDiagnostic(
                diagnostic_id="d1",
                provider="tool",
                evidence_type="made_up",
                file="demo.c",
                line=1,
                column=1,
                rule_id=None,
                severity="warning",
                message="demo",
            )

    def test_empty_diagnostics_are_allowed(self) -> None:
        result = ToolRunResult(
            schema_version=1,
            run_id="run-003",
            tool="clang-sa",
            tool_version="14",
            target_id="fixture-target",
            commit="abc123",
            scope_files=2,
            scope_loc=100,
            status="completed",
            elapsed_seconds=1.0,
            diagnostics=[],
            limitations=["default compile flags only"],
        )

        self.assertEqual(result.diagnostic_count, 0)
        self.assertIn("not proof of safety", result.to_dict()["interpretation"])


if __name__ == "__main__":
    unittest.main()
