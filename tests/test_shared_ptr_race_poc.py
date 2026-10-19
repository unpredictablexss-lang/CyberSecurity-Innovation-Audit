from __future__ import annotations

import json
import hashlib
import tempfile
import unittest
from pathlib import Path

from src.ohscanner.poc.cpp_shared_ptr_race import (
    BuildRecord,
    RunRecord,
    SharedPtrRacePoCResult,
    classify_runs,
    run_detector_on_source,
    load_manifest,
    patch_fixed_source,
    verify_sources,
    write_reports,
)

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "src/ohscanner/poc/harnesses/cpp_shared_ptr_delayed_singleton/manifest.json"


def run_record(revision: str, mode: str, outcome: str) -> RunRecord:
    return RunRecord(
        revision=revision,
        mode=mode,
        command=("binary", mode),
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


def expected_runs(upstream_fix: str = "sanitizer_triggered") -> list[RunRecord]:
    revisions = ("vulnerable", "upstream_fix", "fully_atomic_patch")
    runs = [run_record(item, "single", "clean") for item in revisions]
    for _ in range(3):
        runs.extend(
            [
                run_record("vulnerable", "race", "sanitizer_triggered"),
                run_record("upstream_fix", "race", upstream_fix),
                run_record("fully_atomic_patch", "race", "clean"),
            ]
        )
    return runs


class SharedPtrRacePocTests(unittest.TestCase):
    def test_manifest_binds_detector_rule_and_historical_revisions(self) -> None:
        manifest = load_manifest(MANIFEST)
        self.assertEqual(manifest["detector_id"], "ohscanner.cpp.shared_ptr_race")
        self.assertEqual(manifest["detector_version"], "0.4.0")
        self.assertEqual(
            manifest["revisions"]["vulnerable"]["commit"],
            "bdfafdaafddb01ab7ae13354ce2ada9555d7935c",
        )
        self.assertEqual(
            manifest["revisions"]["upstream_fix"]["commit"],
            "9a3f281120307ec7dcce17fae882dcc4e6a6f4d7",
        )

    def test_source_hashes_and_quotes_are_verified(self) -> None:
        manifest = load_manifest(MANIFEST)
        missing = [
            manifest["revisions"][revision]["path"]
            for revision in ("vulnerable", "upstream_fix")
            if not (ROOT / manifest["revisions"][revision]["path"]).is_file()
        ]
        if missing:
            self.skipTest(
                "optional preserved historical source artifacts are unavailable: "
                + ", ".join(missing)
            )
        records = verify_sources(manifest, ROOT)
        self.assertEqual(
            {item.binding for item in records.values()},
            {"preserved_artifact_hash_verified"},
        )
        self.assertEqual(records["vulnerable"].sha256, records["vulnerable"].verified_sha256)
        self.assertEqual(records["upstream_fix"].sha256, records["upstream_fix"].verified_sha256)

    def test_source_tampering_is_rejected(self) -> None:
        manifest = json.loads(json.dumps(load_manifest(MANIFEST)))
        # Keep the verifier test self-contained. Historical component sources
        # live in ignored audit artifacts and are not part of a clean checkout.
        sample = "if (instance_ == nullptr) {\ninstance_ = temp;\ninstance_.reset();\n"
        sample_hash = hashlib.sha256(sample.encode("utf-8")).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for revision, entry in manifest["revisions"].items():
                path = root / f"{revision}.h"
                path.write_text(sample, encoding="utf-8")
                entry["path"] = path.name
                entry["sha256"] = sample_hash
                entry["required_quotes"] = [
                    "if (instance_ == nullptr) {", "instance_ = temp;", "instance_.reset();"
                ]
            manifest["revisions"]["vulnerable"]["sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "source SHA-256 mismatch"):
                verify_sources(manifest, root)

    def test_real_historical_sources_produce_linked_detector_candidates(self) -> None:
        manifest = load_manifest(MANIFEST)
        missing = [
            manifest["revisions"][revision]["path"]
            for revision in ("vulnerable", "upstream_fix")
            if not (ROOT / manifest["revisions"][revision]["path"]).is_file()
        ]
        if missing:
            self.skipTest(
                "historical detector replay requires locally preserved source artifacts: "
                + ", ".join(missing)
            )
        for revision in ("vulnerable", "upstream_fix"):
            with self.subTest(revision=revision):
                entry = manifest["revisions"][revision]
                source = (ROOT / entry["path"]).read_text(encoding="utf-8")
                summary = run_detector_on_source(entry["path"], source)
                self.assertGreater(summary["finding_count"], 0)
                self.assertTrue(
                    any(
                        obligation["kind"] == "synchronization_proof"
                        and obligation["status"] == "unknown"
                        for finding in summary["findings"]
                        for obligation in finding["evidence_obligations"]
                    )
                )
    def test_patch_revalidation_removes_plain_shared_ptr_write(self) -> None:
        # Verify deterministic patch mechanics with a minimal source shape;
        # historical-source behavior is exercised by the optional replay above.
        source = """std::shared_ptr<T> DelayedSingleton<T>::GetInstance() {
    if (instance_ == nullptr) {
        instance_ = temp;
    }
    return instance_;
}
void DelayedSingleton<T>::DestroyInstance() {}
"""
        patched = patch_fixed_source(source)
        self.assertIn("atomic_store(&instance_, temp)", patched)
        self.assertIn("return atomic_load(&instance_)", patched)
        self.assertNotIn("instance_ = temp;", patched)

    def test_mixed_upstream_fix_is_reproduced_not_hidden(self) -> None:
        self.assertEqual(
            classify_runs(expected_runs("sanitizer_triggered"), repeats=3),
            "stable_reproduced_mixed_fix_residual",
        )

    def test_clean_fix_and_patch_are_recorded_separately(self) -> None:
        self.assertEqual(
            classify_runs(expected_runs("clean"), repeats=3),
            "stable_reproduced_upstream_fix_clean",
        )

    def test_failed_patch_revalidation_is_not_success(self) -> None:
        runs = expected_runs("clean")
        for item in runs:
            if item.revision == "fully_atomic_patch" and item.mode == "race":
                object.__setattr__(item, "outcome", "sanitizer_triggered")
                object.__setattr__(item, "sanitizer_detected", True)
        self.assertEqual(
            classify_runs(runs, repeats=3),
            "patch_revalidation_failed",
        )

    def test_reports_keep_candidate_and_product_limits(self) -> None:
        result = SharedPtrRacePoCResult(
            package_id="cpp-shared-ptr-delayed-singleton-20261014",
            detector_id="ohscanner.cpp.shared_ptr_race",
            detector_version="0.4.0",
            source_binding_status="preserved_artifact_hash_verified",
            builds=(
                BuildRecord(
                    revision="vulnerable",
                    command=("clang++",),
                    exit_code=0,
                    elapsed_seconds=0.1,
                    stdout="",
                    stderr="",
                    outcome="build_success",
                ),
            ),
            runs=tuple(expected_runs()),
            repeats=3,
            outcome="stable_reproduced_mixed_fix_residual",
        )
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "poc.json"
            md_path = Path(directory) / "poc.md"
            write_reports(result, json_path, md_path)
            data = json.loads(json_path.read_text(encoding="utf-8"))
            markdown = md_path.read_text(encoding="utf-8")
        self.assertEqual(data["validated_vulnerability"], 0)
        self.assertEqual(data["candidate_status"], "candidate/unassessed")
        self.assertIn("controlled component-level dynamic evidence", markdown)
        self.assertIn("产品入口", markdown)


if __name__ == "__main__":
    unittest.main()
