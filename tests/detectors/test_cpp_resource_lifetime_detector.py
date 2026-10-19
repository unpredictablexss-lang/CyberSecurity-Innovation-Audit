from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.cpp.resource_lifetime_detector import CppResourceLifetimeDetector
from src.ohscanner.fixture import snapshot_digest


ROOT = Path(__file__).parent / "fixtures" / "cpp_resource_lifetime"


def make_unit(path: Path, parse_status: str = "complete") -> SourceUnit:
    text = path.read_text(encoding="utf-8")
    return SourceUnit(
        path="tests/detectors/fixtures/cpp_resource_lifetime/" + path.name,
        language="cpp",
        text=text,
        sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        parse_status=parse_status,
    )


def context_for(*units: SourceUnit) -> ScanContext:
    return ScanContext(
        request=ScanRequest(
            request_id="test:a-resource-lifetime",
            repository="fixture/ohscanner-resource-lifetime",
            commit="2" * 40,
            snapshot_sha256=snapshot_digest(units),
            target_id="current-component:fixture/ohscanner-resource-lifetime",
            profile_id="fixture-no-build",
            provenance="fixture",
        ),
        units=tuple(sorted(units, key=lambda item: item.path)),
    )


class ResourceLifetimeDetectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
        cls.detector = CppResourceLifetimeDetector()

    def run_case(self, name: str, parse_status: str = "complete"):
        unit = make_unit(ROOT / name, parse_status)
        return self.detector.detect(context_for(unit), (unit,)), unit

    def test_manifest_is_hash_bound_and_covers_control_classes(self) -> None:
        self.assertEqual(
            {item["category"] for item in self.manifest["cases"]},
            {"positive", "fixed", "safe", "unrelated", "unknown"},
        )
        for item in self.manifest["cases"]:
            path = ROOT / item["fixture"]
            self.assertEqual(path.stat().st_size, item["byte_length"])
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), item["sha256"])

    def test_identity_and_positive_controls(self) -> None:
        self.assertEqual(self.detector.detector_id, "ohscanner.cpp.resource_lifetime")
        self.assertEqual(self.detector.version, "0.4.0")
        double_free, _ = self.run_case("positive_double_free.cpp")
        alias_uaf, _ = self.run_case("positive_alias_uaf.cpp")
        self.assertEqual({item.rule_id for item in double_free.findings}, {"ohcpp-resource-lifetime-double-free-candidate-001"})
        self.assertEqual({item.rule_id for item in alias_uaf.findings}, {"ohcpp-resource-lifetime-use-after-free-candidate-002"})
        for run in (double_free, alias_uaf):
            for finding in run.findings:
                self.assertEqual(finding.candidate_cwe, finding.consequence_cwe)
                self.assertEqual(finding.rule_version, "0.4.0")
                self.assertEqual(finding.rule_lineage_id, "A-RES-01:ohcpp-resource-lifetime-candidate")

    def test_fixed_unrelated_and_unknown_controls(self) -> None:
        for name in (
            "fixed_null_after_free.cpp",
            "fixed_reallocate.cpp",
            "unrelated_release.cpp",
            "fixed_detached_callback_cleanup.c",
            "unrelated_recursive_cleanup.c",
        ):
            run, _ = self.run_case(name)
            self.assertEqual(run.status, "completed")
            self.assertEqual(run.findings, ())
        unknown, _ = self.run_case("unknown_partial.cpp", "partial")
        self.assertEqual(unknown.status, "blocked")
        self.assertEqual(unknown.findings, ())

    def test_recursive_cleanup_callback_cycle_candidate(self) -> None:
        run, _ = self.run_case("positive_recursive_callback_cleanup.c")
        recursive = [finding for finding in run.findings if finding.rule_id == "ohcpp-resource-lifetime-recursive-cleanup-candidate-003"]
        self.assertEqual(len(recursive), 1)
        self.assertEqual(recursive[0].candidate_cwe, "CWE-674")
        self.assertEqual(recursive[0].consequence_cwe, "CWE-674")

    def test_recursive_compare_cost_candidate_preserves_partial_status(self) -> None:
        run, _ = self.run_case("positive_recursive_compare_cost.c", "partial")
        candidates = [finding for finding in run.findings if finding.rule_id == "ohcpp-resource-exhaustion-recursive-compare-cost-candidate-005"]
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].candidate_cwe, "CWE-407")
        self.assertEqual(run.status, "blocked")

        safe, _ = self.run_case("safe_recursive_compare_cost.c")
        self.assertFalse(any(f.rule_id == "ohcpp-resource-exhaustion-recursive-compare-cost-candidate-005" for f in safe.findings))
        indexed, _ = self.run_case("safe_recursive_compare_indexed_lookup.c")
        self.assertFalse(any(f.rule_id == "ohcpp-resource-exhaustion-recursive-compare-cost-candidate-005" for f in indexed.findings))

    def test_recursive_tree_amplification_candidate_is_separate(self) -> None:
        release = make_unit(ROOT / "positive_recursive_tree_release.c", "partial")
        patch = make_unit(ROOT / "positive_recursive_tree_patch.c")
        units = tuple(sorted((release, patch), key=lambda item: item.path))
        run = self.detector.detect(context_for(*units), units)
        candidates = [finding for finding in run.findings if finding.rule_id == "ohcpp-resource-exhaustion-tree-amplification-candidate-004"]
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].candidate_cwe, "CWE-674")
        self.assertEqual(candidates[0].identity_quality, "partial")
        self.assertEqual(run.status, "blocked")

        unrelated, _ = self.run_case("unrelated_recursive_tree_cleanup.c")
        self.assertFalse(any(f.rule_id == "ohcpp-resource-exhaustion-tree-amplification-candidate-004" for f in unrelated.findings))

    def test_tree_amplification_and_compare_keep_distinct_rules(self) -> None:
        self.assertNotEqual(
            "ohcpp-resource-exhaustion-tree-amplification-candidate-004",
            "ohcpp-resource-exhaustion-recursive-compare-cost-candidate-005",
        )

    def test_deterministic_output_and_budget(self) -> None:
        first, unit = self.run_case("positive_alias_uaf.cpp")
        second, _ = self.run_case("positive_alias_uaf.cpp")
        self.assertEqual(first, second)
        oversized = SourceUnit(
            path="tests/detectors/fixtures/cpp_resource_lifetime/oversized.cpp",
            language="cpp",
            text="int x;" + " " * (1024 * 1024),
            sha256=hashlib.sha256(("int x;" + " " * (1024 * 1024)).encode("utf-8")).hexdigest(),
            parse_status="complete",
        )
        run = self.detector.detect(context_for(oversized), (oversized,))
        self.assertEqual(run.status, "failed")


if __name__ == "__main__":
    unittest.main()
