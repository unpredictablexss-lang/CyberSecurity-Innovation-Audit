from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from src.ohscanner.poc.cpp_lifetime_uaf import (
    BuildRecord,
    LifetimeUafPocResult,
    RunRecord,
    VARIANTS,
    VULNERABLE,
    classify_runs,
    load_manifest,
    run_detector_on_source,
    verify_harness,
    write_reports,
)

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "src/ohscanner/poc/harnesses/cpp_lifetime_unique_ptr_alias/manifest.json"
HARNESS = MANIFEST.parent / "harness.cpp"


def run_record(variant: str, repeat: int, outcome: str) -> RunRecord:
    return RunRecord(
        variant=variant,
        repeat=repeat,
        command=("binary",),
        exit_code=0 if outcome == "clean" else 66,
        elapsed_seconds=0.01,
        stdout="RESULT=ok",
        stderr="ERROR: AddressSanitizer: heap-use-after-free\n" if outcome == "sanitizer_triggered" else "",
        sanitizer_detected=outcome == "sanitizer_triggered",
        outcome=outcome,
    )


def expected_runs() -> list[RunRecord]:
    runs = []
    for repeat in range(1, 4):
        for variant in VARIANTS:
            outcome = "sanitizer_triggered" if variant in VULNERABLE else "clean"
            runs.append(run_record(variant, repeat, outcome))
    return runs


class LifetimeUafPocTests(unittest.TestCase):
    def test_manifest_and_harness_are_hash_bound(self) -> None:
        manifest = load_manifest(MANIFEST)
        self.assertEqual(manifest["detector_id"], "ohscanner.cpp.lifetime")
        self.assertEqual(manifest["detector_version"], "0.3.0")
        self.assertEqual(verify_harness(manifest, HARNESS), manifest["harness_sha256"])

    def test_detector_covers_all_expanded_invalidation_shapes(self) -> None:
        cases = {
            "reset": "owner.reset(); alias->Use();",
            "null_assignment": "owner = nullptr; alias->Use();",
            "replacement": "owner = std::make_unique<Widget>(); alias->Use();",
            "move_transfer": "{ std::unique_ptr<Widget> next = std::move(owner); } alias->Use();",
        }
        for name, invalidation in cases.items():
            with self.subTest(name=name):
                source = f"""
#include <memory>
#include <utility>
struct Widget {{ void Use() const {{}} }};
void case_{name}() {{
    std::unique_ptr<Widget> owner = std::make_unique<Widget>();
    Widget* alias = owner.get();
    {invalidation}
}}
"""
                summary = run_detector_on_source(f"generated/{name}.cpp", source)
                self.assertGreaterEqual(summary["finding_count"], 1)

    def test_expected_dynamic_matrix_is_stable(self) -> None:
        self.assertEqual(
            classify_runs(expected_runs(), repeats=3),
            "stable_reproduced_and_patch_revalidated",
        )

    def test_failed_control_is_not_success(self) -> None:
        runs = expected_runs()
        object.__setattr__(runs[-1], "outcome", "sanitizer_triggered")
        object.__setattr__(runs[-1], "sanitizer_detected", True)
        self.assertEqual(classify_runs(runs, repeats=3), "patch_revalidation_failed")

    def test_reports_keep_candidate_boundary(self) -> None:
        result = LifetimeUafPocResult(
            package_id="cpp-lifetime-unique-ptr-alias-20261014",
            detector_id="ohscanner.cpp.lifetime",
            detector_version="0.3.0",
            source_binding_status="self_authored_harness_hash_verified",
            harness_sha256="0" * 64,
            builds=(
                BuildRecord("reset_vulnerable", ("clang++",), 0, 0.1, "", "", "build_success"),
            ),
            runs=tuple(expected_runs()),
            repeats=3,
            outcome="stable_reproduced_and_patch_revalidated",
        )
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "poc.json"
            md_path = Path(directory) / "poc.md"
            write_reports(result, json_path, md_path)
            data = json.loads(json_path.read_text(encoding="utf-8"))
            markdown = md_path.read_text(encoding="utf-8")
        self.assertEqual(data["validated_vulnerability"], 0)
        self.assertEqual(data["candidate_status"], "candidate/unassessed")
        self.assertIn("self-authored controlled dynamic evidence", markdown)


if __name__ == "__main__":
    unittest.main()