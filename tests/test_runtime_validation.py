import tempfile
import unittest
from pathlib import Path

from src.validation.cjson_allocator import (
    AllocatorValidationResult,
    BuildRecord,
    RunRecord,
    classify_validation,
    detect_sanitizer,
    write_reports,
)


def build_record(outcome: str = "build_success") -> BuildRecord:
    return BuildRecord(
        command=["clang"],
        exit_code=0 if outcome == "build_success" else 1,
        elapsed_seconds=0.1,
        stdout="",
        stderr="",
        outcome=outcome,
    )


def run_record(
    case: str,
    mode: str,
    outcome: str,
    *,
    exit_code: int | None = 0,
    stderr: str = "",
) -> RunRecord:
    return RunRecord(
        case=case,
        allocator_mode=mode,
        command=["binary", case, mode],
        exit_code=exit_code,
        elapsed_seconds=0.01,
        stdout="",
        stderr=stderr,
        sanitizer_detected=("Sanitizer" in stderr or "runtime error:" in stderr),
        outcome=outcome,
    )


class RuntimeValidationTests(unittest.TestCase):
    def test_detects_sanitizer_markers(self) -> None:
        self.assertTrue(detect_sanitizer("ERROR: AddressSanitizer: SEGV"))
        self.assertTrue(detect_sanitizer("UndefinedBehaviorSanitizer: issue"))
        self.assertTrue(detect_sanitizer("runtime error: null pointer"))
        self.assertFalse(detect_sanitizer("ordinary stderr"))

    def test_classifies_controlled_failure_after_clean_controls(self) -> None:
        runs = [
            run_record("array", "normal", "clean"),
            run_record("object", "normal", "clean"),
            run_record(
                "array",
                "fail-second",
                "sanitizer_triggered",
                exit_code=1,
                stderr="ERROR: AddressSanitizer: SEGV",
            ),
            run_record("object", "fail-second", "clean"),
        ]

        self.assertEqual(
            classify_validation(build_record(), runs),
            "controlled_failure_sanitizer",
        )

    def test_normal_control_failure_marks_harness_invalid(self) -> None:
        runs = [
            run_record("array", "normal", "nonzero_exit", exit_code=1),
            run_record("object", "normal", "clean"),
            run_record(
                "array",
                "fail-second",
                "sanitizer_triggered",
                exit_code=1,
                stderr="ERROR: AddressSanitizer: SEGV",
            ),
        ]

        self.assertEqual(
            classify_validation(build_record(), runs),
            "harness_invalid",
        )

    def test_build_failure_stops_classification(self) -> None:
        self.assertEqual(
            classify_validation(build_record("build_failed"), []),
            "build_failed",
        )

    def test_reports_keep_component_level_interpretation(self) -> None:
        result = AllocatorValidationResult(
            target="/tmp/cjson",
            harness="/tmp/harness.c",
            compiler="clang",
            binary="/tmp/harness",
            repeats=3,
            build=build_record(),
            runs=[
                run_record("array", "normal", "clean"),
                run_record("object", "normal", "clean"),
            ],
            outcome="failure_not_triggered",
        )

        with tempfile.TemporaryDirectory() as directory:
            json_output = Path(directory) / "report.json"
            md_output = Path(directory) / "report.md"
            write_reports(result, json_output, md_output)
            json_text = json_output.read_text(encoding="utf-8")
            md_text = md_output.read_text(encoding="utf-8")

        self.assertIn('"outcome": "failure_not_triggered"', json_text)
        self.assertIn("component-level robustness evidence", json_text)
        self.assertIn("Controlled component-level robustness evidence only", md_text)
        self.assertIn("Overall outcome: failure_not_triggered", md_text)


if __name__ == "__main__":
    unittest.main()
