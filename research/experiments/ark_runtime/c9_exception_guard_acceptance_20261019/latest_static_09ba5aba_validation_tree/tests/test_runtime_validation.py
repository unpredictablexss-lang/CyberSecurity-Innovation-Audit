import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.validation.cjson_allocator import (
    AllocatorValidationResult,
    BuildRecord,
    RunRecord,
    classify_validation,
    detect_sanitizer,
    run_cjson_allocator_validation,
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


class ValidationImageContractTests(unittest.TestCase):
    def test_dockerfile_uses_packages_present_in_ubuntu_2204(self) -> None:
        dockerfile = (
            Path(__file__).resolve().parents[1]
            / "docker"
            / "validation"
            / "Dockerfile"
        ).read_text(encoding="utf-8")

        self.assertIn("clang-14", dockerfile)
        self.assertIn("libclang-common-14-dev", dockerfile)
        self.assertNotIn("libclang-rt-14-dev", dockerfile)


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

    def test_mixed_repetitions_are_inconclusive(self) -> None:
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
            run_record("array", "fail-second", "nonzero_exit", exit_code=139),
            run_record("object", "fail-second", "clean"),
        ]

        self.assertEqual(classify_validation(build_record(), runs), "inconclusive")

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

    def test_runner_stops_after_invalid_normal_control(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "cjson"
            target.mkdir()
            for name in ("cJSON.c", "cJSON_Utils.c", "cJSON.h", "cJSON_Utils.h"):
                (target / name).touch()
            harness = root / "harness.c"
            harness.touch()
            fake_results = [
                (0, 0.1, "", "", False),
                (-11, 0.01, "", "", False),
                (0, 0.01, "pointer=/child\n", "", False),
            ]

            with patch(
                "src.validation.cjson_allocator._run_process",
                side_effect=fake_results,
            ) as process:
                result = run_cjson_allocator_validation(
                    target=target,
                    harness=harness,
                    binary=root / "harness",
                    repeats=3,
                )

        self.assertEqual(result.outcome, "harness_invalid")
        self.assertEqual(len(result.runs), 2)
        self.assertEqual(process.call_count, 3)
        self.assertIn("-no-pie", process.call_args_list[0].args[0])

    def test_runner_rejects_wrong_source_commit_before_build(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "cjson"
            target.mkdir()
            for name in ("cJSON.c", "cJSON_Utils.c", "cJSON.h", "cJSON_Utils.h"):
                (target / name).write_text("/* fixture */\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(target), "init", "-q"], check=True)
            subprocess.run(["git", "-C", str(target), "add", "."], check=True)
            subprocess.run(
                [
                    "git", "-C", str(target),
                    "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                    "commit", "-qm", "fixture",
                ],
                check=True,
            )
            harness = root / "harness.c"
            harness.touch()

            with patch("src.validation.cjson_allocator._run_process") as process:
                with self.assertRaisesRegex(ValueError, "Target commit mismatch"):
                    run_cjson_allocator_validation(
                        target=target,
                        harness=harness,
                        binary=root / "harness",
                        expected_commit="0" * 40,
                    )

        process.assert_not_called()

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
