from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.ohscanner.poc.cpp_shared_ptr_race import (
    BuildRecord,
    RunRecord,
    binding_manifest_sha256,
    build_poc_binding,
    classify_runs,
    detect_tsan,
    validate_materialized_revision,
    verify_poc_binding,
    write_reports,
    SharedPtrRacePoCResult,
)


def build_record(outcome: str = "build_success") -> BuildRecord:
    return BuildRecord(
        revision="vulnerable",
        command=("clang++",),
        exit_code=0 if outcome == "build_success" else 1,
        elapsed_seconds=0.1,
        stdout="",
        stderr="",
        outcome=outcome,
    )


def run_record(outcome: str, *, stderr: str = "", exit_code: int | None = 0) -> RunRecord:
    sanitizer, race, uaf = detect_tsan(stderr)
    return RunRecord(
        revision="vulnerable",
        repeat=1,
        command=("harness",),
        exit_code=exit_code,
        elapsed_seconds=0.1,
        stdout="",
        stderr=stderr,
        timed_out=outcome == "timeout",
        sanitizer_detected=sanitizer,
        race_detected=race,
        use_after_free_detected=uaf,
        outcome=outcome,
        log_sha256="0" * 64,
    )


class SharedPtrRacePoCTests(unittest.TestCase):
    def test_detects_tsan_race_and_uaf(self) -> None:
        sanitizer, race, uaf = detect_tsan(
            "WARNING: ThreadSanitizer: data race\nheap-use-after-free\n"
            "SUMMARY: ThreadSanitizer: data race"
        )
        self.assertTrue(sanitizer)
        self.assertTrue(race)
        self.assertTrue(uaf)
        self.assertEqual(detect_tsan("clean"), (False, False, False))

    def test_vulnerable_stability_classification(self) -> None:
        triggered = run_record(
            "sanitizer_triggered",
            stderr="WARNING: ThreadSanitizer: data race",
            exit_code=66,
        )
        clean = run_record("clean")
        self.assertEqual(
            classify_runs("vulnerable", build_record(), (triggered, triggered)),
            ("stable_reproduced", 2),
        )
        self.assertEqual(
            classify_runs("vulnerable", build_record(), (triggered, clean)),
            ("flaky_trigger", 1),
        )
        self.assertEqual(
            classify_runs("vulnerable", build_record(), (clean, clean)),
            ("no_trigger", 0),
        )

    def test_fixed_clean_is_patch_revalidation_not_safe(self) -> None:
        clean = run_record("clean")
        status, count = classify_runs("fixed", build_record(), (clean, clean))
        self.assertEqual(status, "patch_revalidation_passed")
        self.assertEqual(count, 0)
        triggered = run_record(
            "sanitizer_triggered",
            stderr="WARNING: ThreadSanitizer: data race",
            exit_code=66,
        )
        self.assertEqual(
            classify_runs("fixed", build_record(), (clean, triggered)),
            ("patch_revalidation_failed", 1),
        )

    def test_build_failure_and_empty_runs_are_not_reproduced(self) -> None:
        self.assertEqual(
            classify_runs("vulnerable", build_record("build_failed"), ()),
            ("build_failed", 0),
        )
        self.assertEqual(
            classify_runs("vulnerable", build_record(), ()),
            ("not_run", 0),
        )

    def test_binding_tampering_is_rejected(self) -> None:
        binding = {
            "schema_version": 1,
            "kind": "cpp_shared_ptr_race_poc_binding",
            "repository": "openharmony/commonlibrary_c_utils",
            "source_paths": [
                "base/include/nocopyable.h",
                "base/include/singleton.h",
            ],
            "revisions": {
                role: {
                    "commit": value["commit"],
                    "git_tree": value["git_tree"],
                    "sources": value["sources"],
                }
                for role, value in __import__(
                    "src.ohscanner.poc.cpp_shared_ptr_race", fromlist=["EXPECTED_REVISIONS"]
                ).EXPECTED_REVISIONS.items()
            },
        }
        digest = binding_manifest_sha256(binding)
        verify_poc_binding(binding, digest)
        binding["revisions"]["vulnerable"]["sources"]["base/include/singleton.h"]["source_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            verify_poc_binding(binding, digest)

    def test_materialized_revision_records_logs_and_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            with patch(
                "src.ohscanner.poc.cpp_shared_ptr_race._build_revision",
                return_value=build_record(),
            ), patch(
                "src.ohscanner.poc.cpp_shared_ptr_race._run_process",
                return_value=(66, 0.1, "", "WARNING: ThreadSanitizer: data race", False, 1024),
            ):
                result = validate_materialized_revision(
                    role="vulnerable",
                    revision="vulnerable",
                    commit="a" * 40,
                    git_tree="b" * 40,
                    source_binding={},
                    target=target,
                    compiler="clang++",
                    repeats=2,
                    build_timeout=1.0,
                    run_timeout=1.0,
                    use_setarch=False,
                    log_dir=root / "logs",
                )
        self.assertEqual(result.status, "stable_reproduced")
        self.assertEqual(result.trigger_count, 2)
        self.assertEqual(len(result.runs), 2)
        self.assertTrue(all(run.race_detected for run in result.runs))

    def test_reports_preserve_interpretation_boundary(self) -> None:
        result = SharedPtrRacePoCResult(
            schema_version=1,
            package_id="test",
            repository="openharmony/commonlibrary_c_utils",
            binding_status="draft_unpinned",
            binding_manifest_sha256="1" * 64,
            harness_sha256="2" * 64,
            environment={"compiler": "clang++"},
            repeats=1,
            revisions={},
            poc_state="stable_reproduced",
            patch_revalidation="passed",
            interpretation="component-level only",
            limitations=("product entry unknown",),
        )
        with tempfile.TemporaryDirectory() as directory:
            json_out = Path(directory) / "poc.json"
            md_out = Path(directory) / "poc.md"
            write_reports(result, json_out, md_out)
            self.assertIn('"poc_state": "stable_reproduced"', json_out.read_text(encoding="utf-8"))
            self.assertIn("product entry unknown", md_out.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
