from __future__ import annotations

import hashlib
import json
import shutil
import unittest
from pathlib import Path

from research.experiments.cpp.run_four_class_controls import (
    load_manifest,
    run_detector_matrix,
    verify_manifest_sources,
    verify_patches,
)


ROOT = Path(__file__).resolve().parents[1]
BASELINE_MANIFEST = ROOT / "research/tests/cpp_detector_controls/manifest.json"
IMPLEMENTATION_MANIFEST = (
    ROOT / "research/tests/cpp_detector_controls_impl_20261015/manifest.json"
)
IMPLEMENTATION_RESULTS = (
    ROOT
    / "research/evidence/cpp/implementation_bound_controls_20261015/run-002/results.json"
)


class CppFourClassControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = load_manifest(IMPLEMENTATION_MANIFEST)
        cls.baseline_manifest = load_manifest(BASELINE_MANIFEST)

    def test_manifest_binds_every_source_hash_and_snapshot(self) -> None:
        identities = verify_manifest_sources(self.manifest)
        self.assertEqual(len(identities), len(self.manifest["controls"]))
        self.assertEqual(
            {item["control_id"] for item in identities},
            {item["id"] for item in self.manifest["controls"]},
        )
        for item in identities:
            self.assertEqual(len(item["sha256"]), 64)
            self.assertEqual(len(item["git_blob_sha1"]), 40)
            self.assertGreater(item["bytes"], 0)

    def test_implementation_package_preserves_baseline_and_binds_sources(self) -> None:
        self.assertEqual(
            hashlib.sha256(BASELINE_MANIFEST.read_bytes()).hexdigest(),
            "8065687ef494a26762af05c3e91828648365a88205481e41d5cf78088f23e9f2",
        )
        self.assertEqual(
            self.baseline_manifest["detectors"]["ohscanner.cpp.shared_ptr_race"]["version"],
            "0.4.0",
        )
        self.assertEqual(
            self.baseline_manifest["detectors"]["ohscanner.cpp.lifetime"]["version"],
            "0.3.0",
        )
        self.assertEqual(
            self.manifest["provenance"]["derived_from_baseline_manifest"]["sha256"],
            hashlib.sha256(BASELINE_MANIFEST.read_bytes()).hexdigest(),
        )
        expected_versions = {
            "ohscanner.cpp.shared_ptr_race": "0.5.0",
            "ohscanner.cpp.lifetime": "0.4.0",
        }
        for detector_id, expected_version in expected_versions.items():
            binding = self.manifest["implementation_bindings"][detector_id]
            source = ROOT / binding["source"]["path"]
            self.assertEqual(binding["detector_version"], expected_version)
            self.assertEqual(
                hashlib.sha256(source.read_bytes()).hexdigest(),
                binding["source"]["sha256"],
            )
            self.assertEqual(
                binding["git_tree_sha1"],
                self.manifest["provenance"]["authoring_checkout"]["tree"],
            )
            self.assertTrue(binding["scope_id"])
            self.assertTrue(binding["profile_id"])
            self.assertIn("candidate/unassessed", binding["profile"])

    def test_each_detector_has_four_classes_and_required_patterns(self) -> None:
        required_categories = {"vulnerable", "fixed", "safe", "unrelated"}
        required_patterns = {
            "DelayedSingleton",
            "stable owner pointer",
            "explicit lock",
            "atomic exchange",
            "atomic compare-exchange",
            "mixed atomic/non-atomic",
            "reset",
            "owner assignment",
            "owner replacement",
            "restricted move transfer",
            "raw alias",
            "common false-positive shape",
        }
        observed_patterns = {
            pattern
            for control in self.manifest["controls"]
            for pattern in control["patterns"]
        }
        self.assertTrue(required_patterns <= observed_patterns)
        for detector_id in self.manifest["detectors"]:
            selected = [
                item
                for item in self.manifest["controls"]
                if item["detector_id"] == detector_id
            ]
            self.assertEqual(
                {item["category"] for item in selected},
                required_categories,
            )

    def test_fixed_controls_bind_real_applied_patch_artifacts(self) -> None:
        fixed = [
            item for item in self.manifest["controls"] if item["category"] == "fixed"
        ]
        self.assertTrue(fixed)
        for item in fixed:
            self.assertIn("patch", item)
            self.assertEqual(
                item["patch"]["kind"],
                "authored_control_remediation_patch",
            )
            self.assertEqual(
                item["patch"]["upstream_status"],
                "not_claimed_as_upstream_product_patch",
            )
        if not shutil.which("patch"):
            self.skipTest("patch is required to verify authored remediation patches")
        results = verify_patches(self.manifest)
        for item in results:
            self.assertIn(item["status"], {"passed", "not_applicable"})
            if item["status"] == "passed":
                self.assertEqual(item["patched_sha256"], item["fixed_sha256"])
                self.assertEqual(
                    item["command"]["argv"][
                        item["command"]["argv"].index("--fuzz=0")
                    ],
                    "--fuzz=0",
                )

    def test_detector_matrix_matches_control_expectations(self) -> None:
        results = run_detector_matrix(self.manifest)
        for item in results:
            self.assertTrue(item["detector_version_binding"]["observed"])
            implementation_version = self.manifest["implementation_bindings"][
                item["detector_id"]
            ]["detector_version"]
            self.assertEqual(
                item["detector_version_binding"]["observed"],
                implementation_version,
            )
            self.assertNotEqual(
                item["detector_version_binding"]["observed"],
                item["detector_version_binding"]["manifest"],
            )
        failures = [
            {"control_id": item["control_id"], "failures": item["failures"]}
            for item in results
            if item["status_result"] != "passed"
        ]
        self.assertEqual(failures, [])

    def test_recorded_native_controls_bind_exact_execution_and_results(self) -> None:
        recorded = json.loads(IMPLEMENTATION_RESULTS.read_text(encoding="utf-8"))
        self.assertEqual(
            recorded["manifest"]["sha256"],
            hashlib.sha256(IMPLEMENTATION_MANIFEST.read_bytes()).hexdigest(),
        )
        native = recorded["stages"]["native_controls"]
        items = native["items"]
        compiler = recorded["toolchain"]["compiler"]["command"]
        repeats = recorded["toolchain"]["repeats"]
        self.assertEqual(native["status"], "passed")
        self.assertEqual(len(items), len(self.manifest["controls"]))
        self.assertEqual(
            {item["control_id"] for item in items},
            {item["id"] for item in self.manifest["controls"]},
        )
        for item in items:
            with self.subTest(control=item["control_id"]):
                build_argv = item["build"]["command"]["argv"]
                self.assertIsInstance(build_argv, list)
                self.assertTrue(build_argv)
                self.assertTrue(all(isinstance(arg, str) for arg in build_argv))
                self.assertEqual(build_argv[0], compiler)
                sanitizer_flag = {
                    "address": "-fsanitize=address",
                    "thread": "-fsanitize=thread",
                }[item["sanitizer"]]
                self.assertIn(sanitizer_flag, build_argv)
                self.assertEqual(len(item["runs"]), repeats)
                self.assertEqual(
                    [run["repeat"] for run in item["runs"]],
                    list(range(1, repeats + 1)),
                )
                for run in item["runs"]:
                    self.assertTrue(run["command"]["argv"])
                    self.assertTrue(all(isinstance(arg, str) for arg in run["command"]["argv"]))
                    self.assertEqual(run["observed_outcome"], run["expected_outcome"])
                    self.assertEqual(run["status"], "passed")
                    self.assertRegex(run["log_sha256"], r"^[0-9a-f]{64}$")
                self.assertRegex(item["source_sha256"], r"^[0-9a-f]{64}$")
                self.assertRegex(item["build"]["binary_sha256"], r"^[0-9a-f]{64}$")
                self.assertRegex(item["build"]["log_sha256"], r"^[0-9a-f]{64}$")
                self.assertEqual(item["status"], "passed")
                self.assertEqual(item["failures"], [])

    def test_negative_controls_are_not_accuracy_or_safety_claims(self) -> None:
        self.assertFalse(self.manifest["is_independent_holdout"])
        self.assertFalse(self.manifest["accuracy_metrics_permitted"])
        self.assertIn("precision", self.manifest["metric_policy"]["prohibited"])
        self.assertIn("recall", self.manifest["metric_policy"]["prohibited"])
        self.assertIn(
            "not a global safe or miss verdict",
            self.manifest["metric_policy"]["negative_control_rule"],
        )
        self.assertTrue(
            any(
                "不是独立 holdout" in item or "not independent" in item.lower()
                for item in self.manifest["limitations"]
            )
        )
        encoded = json.dumps(self.manifest, ensure_ascii=False).lower()
        self.assertNotIn("zero false positive", encoded)
        self.assertNotIn("zero false negative", encoded)


if __name__ == "__main__":
    unittest.main()
