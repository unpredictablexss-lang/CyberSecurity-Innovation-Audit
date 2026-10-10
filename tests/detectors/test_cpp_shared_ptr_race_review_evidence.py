from __future__ import annotations

import copy
import unittest

from src.ohscanner.contracts import ScanContext, ScanRequest
from src.ohscanner.detectors.cpp.shared_ptr_race_detector import (
    SharedPtrRaceDetector,
)
from src.ohscanner.detectors.cpp.shared_ptr_race_review import (
    build_shared_ptr_race_review_evidence,
    canonical_manifest_sha256,
    canonical_review_json,
    review_evidence_sha256,
    verify_review_evidence,
)
from src.ohscanner.fixture import snapshot_digest
from tests.detectors.shared_ptr_race_fixture_support import (
    SHARED_PTR_RACE_FIXTURES,
    load_manifest,
    load_shared_ptr_race_units,
)


def _class_name(category: str) -> str:
    for prefix in (
        "vulnerable",
        "fixed",
        "unrelated",
        "safe",
        "unknown",
        "not_applicable",
    ):
        if category.startswith(prefix):
            return prefix
    raise AssertionError(f"unsupported fixture category: {category}")


class SharedPtrRaceReviewEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = load_manifest(SHARED_PTR_RACE_FIXTURES)
        cls.manifest_sha256 = canonical_manifest_sha256(cls.manifest)
        cls.units = load_shared_ptr_race_units()
        cls.by_path = {unit.path: unit for unit in cls.units}

    def context_for(self, class_name: str) -> ScanContext:
        paths = {
            item["path"]
            for item in self.manifest["units"]
            if _class_name(item["fixture_category"]) == class_name
        }
        units = tuple(unit for unit in self.units if unit.path in paths)
        self.assertTrue(units)
        provenance = self.manifest["provenance"]
        return ScanContext(
            request=ScanRequest(
                request_id="test-review:" + class_name,
                repository=provenance["repository"],
                commit=provenance["commit"],
                snapshot_sha256=snapshot_digest(units),
                target_id="current-component:" + provenance["repository"],
                profile_id=provenance["profile_id"],
                provenance="fixture",
            ),
            units=units,
        )

    def evidence_for(self, class_name: str):
        context = self.context_for(class_name)
        run = SharedPtrRaceDetector().detect(context, context.units)
        return (
            context,
            run,
            build_shared_ptr_race_review_evidence(
                context,
                run,
                self.manifest,
                self.manifest_sha256,
            ),
        )

    def verify(self, evidence, context, run, manifest=None, manifest_sha256=None):
        selected_manifest = self.manifest if manifest is None else manifest
        selected_hash = self.manifest_sha256 if manifest_sha256 is None else manifest_sha256
        verify_review_evidence(
            evidence,
            context,
            run,
            selected_manifest,
            selected_hash,
        )

    def assert_saved_record_rejected(self, mutate) -> None:
        context, run, evidence = self.evidence_for("vulnerable")
        mutate(evidence)
        with self.assertRaisesRegex(
            ValueError,
            "does not match trusted context, run and fixture manifest",
        ):
            self.verify(evidence, context, run)

    def test_candidate_findings_bind_exact_source_hash_location_and_rule(self) -> None:
        context, run, evidence = self.evidence_for("vulnerable")
        self.assertEqual(run.status, "completed")
        self.assertEqual(evidence["evidence_class"], "vulnerable")
        self.assertEqual(evidence["fixture_manifest_sha256"], self.manifest_sha256)
        self.assertGreater(len(evidence["finding_bindings"]), 0)
        for binding in evidence["finding_bindings"]:
            unit = self.by_path[binding["file"]]
            source_line = unit.text.splitlines()[binding["line"] - 1]
            self.assertEqual(binding["source_sha256"], unit.sha256)
            self.assertIn(binding["symbol"], source_line)
            self.assertEqual(
                binding["rule_id"],
                "ohcpp-shared-ptr-race-candidate-001",
            )
            self.assertEqual(binding["evidence_type"], "syntax")
            self.assertEqual(binding["candidate_cwe"], "CWE-362")
            self.assertEqual(binding["assessment"], "candidate")
            self.assertEqual(binding["review_status"], "unassessed")
            self.assertRegex(binding["finding_binding_id"], r"^[a-f0-9]{64}$")
        self.verify(evidence, context, run)
        self.assertEqual(
            review_evidence_sha256(evidence),
            review_evidence_sha256(
                __import__("json").loads(canonical_review_json(evidence))
            ),
        )

    def test_fixed_safe_and_unrelated_are_separate_completed_scopes(self) -> None:
        for class_name in ("fixed", "safe", "unrelated"):
            with self.subTest(class_name=class_name):
                context, run, evidence = self.evidence_for(class_name)
                self.assertEqual(run.status, "completed")
                self.assertEqual(run.findings, ())
                self.assertEqual(evidence["evidence_class"], class_name)
                self.assertEqual(evidence["finding_bindings"], [])
                self.assertEqual(
                    evidence["scope"]["coverage_interpretation"],
                    "analyzed_selected_scope_only",
                )
                self.assertEqual(
                    evidence["scope"]["benchmark_outcome"],
                    "not_assigned",
                )
                self.verify(evidence, context, run)

    def test_partial_failed_not_run_and_incomplete_are_unknown_not_miss(self) -> None:
        context, run, evidence = self.evidence_for("unknown")
        self.assertEqual(run.status, "blocked")
        self.assertEqual(evidence["evidence_class"], "unknown")
        self.assertEqual(
            evidence["scope"]["coverage_interpretation"],
            "unknown_incomplete_analysis",
        )
        self.assertEqual(evidence["scope"]["benchmark_outcome"], "not_assigned")
        statuses = {item.parse_status for item in context.units}
        self.assertIn("partial", statuses)
        self.assertIn("failed", statuses)
        self.assertIn("not_run", statuses)
        self.assertTrue(any("parse_status=partial" in item for item in run.limitations))
        self.assertTrue(any("parse_status=failed" in item for item in run.limitations))
        self.assertTrue(any("parse_status=not_run" in item for item in run.limitations))
        self.assertTrue(
            any("outside a modeled function span" in item for item in run.limitations)
        )

    def test_review_rejects_saved_record_semantic_tampering(self) -> None:
        cases = {
            "top-level evidence class": lambda value: value.__setitem__(
                "evidence_class", "fixed"
            ),
            "artifact category": lambda value: value["source_artifacts"][0].__setitem__(
                "fixture_category", "fixed_atomic_shared_ptr"
            ),
            "artifact class": lambda value: value["source_artifacts"][0].__setitem__(
                "evidence_class", "fixed"
            ),
            "parse issues": lambda value: value["source_artifacts"][0].__setitem__(
                "parse_issues", ["forged"]
            ),
            "empty analyzed scope": lambda value: value["scope"].__setitem__(
                "analyzed_files", []
            ),
            "finding outside analyzed scope": lambda value: value["scope"].__setitem__(
                "analyzed_files", value["scope"]["analyzed_files"][1:]
            ),
            "source hash": lambda value: value["source_artifacts"][0].__setitem__(
                "sha256", "0" * 64
            ),
            "finding source hash": lambda value: value["finding_bindings"][0].__setitem__(
                "source_sha256", "0" * 64
            ),
            "finding identity": lambda value: value["finding_bindings"][0].__setitem__(
                "finding_binding_id", "0" * 64
            ),
            "finding line": lambda value: value["finding_bindings"][0].__setitem__(
                "line", 0
            ),
            "duplicate artifact": lambda value: value.__setitem__(
                "source_artifacts",
                value["source_artifacts"] + value["source_artifacts"][:1],
            ),
        }
        for name, mutate in cases.items():
            with self.subTest(case=name):
                self.assert_saved_record_rejected(mutate)

    def test_review_rejects_mixed_evidence_classes(self) -> None:
        vulnerable = self.context_for("vulnerable")
        fixed = self.context_for("fixed")
        units = tuple(sorted(vulnerable.units + fixed.units, key=lambda item: item.path))
        context = ScanContext(
            request=ScanRequest(
                request_id="test-review:mixed",
                repository=self.manifest["provenance"]["repository"],
                commit=self.manifest["provenance"]["commit"],
                snapshot_sha256=snapshot_digest(units),
                target_id="current-component:" + self.manifest["provenance"]["repository"],
                profile_id=self.manifest["provenance"]["profile_id"],
                provenance="fixture",
            ),
            units=units,
        )
        run = SharedPtrRaceDetector().detect(context, context.units)
        with self.assertRaisesRegex(ValueError, "cannot be mixed"):
            build_shared_ptr_race_review_evidence(
                context,
                run,
                self.manifest,
                self.manifest_sha256,
            )

    def test_manifest_hash_is_required_and_binds_canonical_content(self) -> None:
        context = self.context_for("vulnerable")
        run = SharedPtrRaceDetector().detect(context, context.units)
        with self.assertRaisesRegex(ValueError, "manifest hash"):
            build_shared_ptr_race_review_evidence(
                context, run, self.manifest, "not-a-sha256"
            )

        tampered = copy.deepcopy(self.manifest)
        tampered["units"][0]["fixture_category"] = "fixed_atomic_shared_ptr"
        with self.assertRaisesRegex(ValueError, "manifest hash mismatch"):
            build_shared_ptr_race_review_evidence(
                context, run, tampered, self.manifest_sha256
            )

        recomputed = canonical_manifest_sha256(tampered)
        context, run, evidence = self.evidence_for("vulnerable")
        with self.assertRaisesRegex(
            ValueError,
            "does not match trusted context, run and fixture manifest",
        ):
            self.verify(evidence, context, run, tampered, recomputed)

    def test_review_rejects_abnormal_locations(self) -> None:
        context, run, evidence = self.evidence_for("vulnerable")
        evidence["finding_bindings"][0]["line"] = 0
        with self.assertRaisesRegex(
            ValueError,
            "does not match trusted context, run and fixture manifest",
        ):
            self.verify(evidence, context, run)

        _context, _run, evidence = self.evidence_for("vulnerable")
        evidence["finding_bindings"][0]["column"] = 10**6
        with self.assertRaisesRegex(
            ValueError,
            "does not match trusted context, run and fixture manifest",
        ):
            self.verify(evidence, context, run)


if __name__ == "__main__":
    unittest.main()
