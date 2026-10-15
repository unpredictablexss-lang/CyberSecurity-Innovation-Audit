from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from src.ohscanner.poc.cpp_shared_ptr_jsproxy import (
    RunRecord,
    _fixed_control_source,
    _patched_atomic_source,
    classify,
    run_detector,
    verify_sources,
)

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "src/ohscanner/poc/harnesses/cpp_shared_ptr_jsproxy/manifest.json"


def run_record(variant: str, mode: str, repeat: int, outcome: str) -> RunRecord:
    return RunRecord(
        variant=variant,
        mode=mode,
        repeat=repeat,
        command=("poc", mode),
        exit_code=66 if outcome == "sanitizer_triggered" else 0,
        elapsed_seconds=0.01,
        stdout="RESULT=ok",
        stderr=(
            "WARNING: ThreadSanitizer: data race\n"
            if outcome == "sanitizer_triggered"
            else ""
        ),
        sanitizer_detected=outcome == "sanitizer_triggered",
        outcome=outcome,
    )


def expected_runs(
    vulnerable: str = "sanitizer_triggered",
    fixed: str = "clean",
    patched: str = "clean",
) -> list[RunRecord]:
    runs: list[RunRecord] = []
    for variant in ("vulnerable", "fixed_control_mutex", "patched_atomic_minimal"):
        runs.append(run_record(variant, "single", 1, "clean"))
        runs.append(run_record(variant, "unrelated", 1, "clean"))
    outcomes = {
        "vulnerable": vulnerable,
        "fixed_control_mutex": fixed,
        "patched_atomic_minimal": patched,
    }
    for mode in ("race", "close_get_entry"):
        for repeat in range(1, 4):
            for variant, outcome in outcomes.items():
                runs.append(run_record(variant, mode, repeat, outcome))
    return runs


class SharedPtrJsProxyPocTests(unittest.TestCase):
    def test_manifest_binds_candidate_detector_rule_and_git_identity(self) -> None:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(manifest["repository"], "openharmony/distributeddatamgr_kv_store")
        self.assertEqual(manifest["commit"], "acfb22aac16161d8fb0cefb6cc9b92f04f489a80")
        self.assertEqual(manifest["git_tree"], "3b92c53fde616d5a3f9487b0c295670a42c63023")
        self.assertEqual(manifest["detector_id"], "ohscanner.cpp.shared_ptr_race")
        self.assertEqual(manifest["detector_version"], "0.5.0")
        self.assertEqual(manifest["rule_id"], "ohcpp-shared-ptr-race-candidate-001")
        self.assertEqual(len(manifest["candidate_ids"]), 2)
        harness = ROOT / "src/ohscanner/poc/harnesses/cpp_shared_ptr_jsproxy/harness.cpp"
        self.assertEqual(
            hashlib.sha256(harness.read_bytes()).hexdigest(),
            manifest["harness_sha256"],
        )
        runner = ROOT / manifest["poc_runner_path"]
        self.assertEqual(
            hashlib.sha256(runner.read_bytes()).hexdigest(),
            manifest["poc_runner_sha256"],
        )
        detector = ROOT / manifest["detector_source_path"]
        self.assertEqual(
            hashlib.sha256(detector.read_bytes()).hexdigest(),
            manifest["detector_source_sha256"],
        )

    def test_exact_git_objects_and_source_hashes_are_verified(self) -> None:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        source, call_sources, blobs = verify_sources(manifest)
        self.assertTrue(source.verified)
        self.assertEqual(source.blob, manifest["source_blob"])
        self.assertEqual(source.sha256, manifest["source_sha256"])
        self.assertEqual(len(call_sources), 9)
        self.assertTrue(all(item.verified for item in call_sources))
        self.assertTrue(all(item.sha256 != item.checkout_sha256 for item in (source, *call_sources)))
        self.assertEqual(len(blobs), 10)

    def test_source_tampering_is_rejected(self) -> None:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        manifest["source_sha256"] = "0" * 64
        with self.assertRaisesRegex(RuntimeError, "source binding mismatch"):
            verify_sources(manifest)

    def test_exact_vulnerable_source_produces_two_unknown_candidates(self) -> None:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        source, _, blobs = verify_sources(manifest)
        record = run_detector("vulnerable", source.path, blobs[source.path])
        self.assertEqual(record.status, "completed")
        self.assertEqual(record.finding_count, 2)
        self.assertEqual(
            {item["line"] for item in record.findings},
            {37, 42},
        )
        self.assertTrue(
            all(
                obligation["status"] == "unknown"
                for item in record.findings
                for obligation in item["evidence_obligations"]
            )
        )

    def test_fixed_control_and_minimal_patch_remove_detector_findings(self) -> None:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        source, _, blobs = verify_sources(manifest)
        exact = blobs[source.path].decode("utf-8")
        fixed = _fixed_control_source(exact).encode("utf-8")
        patched = _patched_atomic_source(exact).encode("utf-8")
        self.assertIn("std::lock_guard<std::mutex> lock(instanceMutex_);", fixed.decode("utf-8"))
        self.assertIn("std::atomic_store(&instance_, std::move(instance));", patched.decode("utf-8"))
        self.assertIn("return std::atomic_load(&instance_);", patched.decode("utf-8"))
        for name, data in (("fixed_control_mutex", fixed), ("patched_atomic_minimal", patched)):
            with self.subTest(variant=name):
                record = run_detector(name, source.path, data)
                self.assertEqual(record.status, "completed")
                self.assertEqual(record.finding_count, 0)

    def test_stable_vulnerable_and_clean_repairs_are_classified(self) -> None:
        self.assertEqual(
            classify(expected_runs(), repeats=3),
            "stable_reproduced_and_patch_revalidated",
        )

    def test_failed_patch_revalidation_is_not_success(self) -> None:
        self.assertEqual(
            classify(expected_runs(patched="sanitizer_triggered"), repeats=3),
            "patch_revalidation_failed",
        )

    def test_unreproduced_vulnerable_race_is_not_promoted(self) -> None:
        self.assertEqual(
            classify(expected_runs(vulnerable="clean"), repeats=3),
            "not_reproduced",
        )


if __name__ == "__main__":
    unittest.main()
