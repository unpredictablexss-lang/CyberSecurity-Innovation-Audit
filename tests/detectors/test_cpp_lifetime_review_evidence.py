from __future__ import annotations

import hashlib
import json
import unittest

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.cpp.lifetime_detector import (
    LifetimeOwnershipGuardDetector,
)
from src.ohscanner.detectors.cpp.lifetime_review import (
    build_cpp_lifetime_review_evidence,
    canonical_review_json,
    review_evidence_sha256,
    verify_review_evidence,
)
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.runner import DetectorRegistry, run_all
from tests.detectors.fixture_support import (
    LIFETIME_FIXTURES,
    load_manifest,
    load_units,
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


class LifetimeReviewEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest_path = LIFETIME_FIXTURES / "manifest.json"
        cls.manifest = load_manifest(LIFETIME_FIXTURES)
        cls.manifest_sha256 = hashlib.sha256(
            cls.manifest_path.read_bytes()
        ).hexdigest()
        cls.units = load_units(LIFETIME_FIXTURES)
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
        run = LifetimeOwnershipGuardDetector().detect(context, context.units)
        return (
            context,
            run,
            build_cpp_lifetime_review_evidence(
                context,
                run,
                self.manifest,
                self.manifest_sha256,
            ),
        )

    def test_candidate_findings_bind_exact_source_hash_location_and_rule(self) -> None:
        context, run, evidence = self.evidence_for("vulnerable")
        self.assertEqual(run.status, "completed")
        self.assertEqual(len(run.findings), 3)
        self.assertEqual(evidence["evidence_class"], "vulnerable")
        self.assertEqual(evidence["fixture_manifest_sha256"], self.manifest_sha256)
        self.assertEqual(len(evidence["finding_bindings"]), 3)
        for binding in evidence["finding_bindings"]:
            unit = self.by_path[binding["file"]]
            source_line = unit.text.splitlines()[binding["line"] - 1]
            self.assertEqual(binding["source_sha256"], unit.sha256)
            self.assertIn(binding["symbol"], source_line)
            self.assertEqual(binding["rule_id"], "ohcpp-lifetime-unique-raw-alias-reset-001")
            self.assertEqual(binding["evidence_type"], "syntax")
            self.assertEqual(binding["assessment"], "candidate")
            self.assertEqual(binding["review_status"], "unassessed")
            self.assertRegex(binding["finding_binding_id"], r"^[a-f0-9]{64}$")
        verify_review_evidence(evidence, context)
        self.assertEqual(review_evidence_sha256(evidence), hashlib.sha256(
            canonical_review_json(evidence).encode("utf-8")
        ).hexdigest())

    def test_safe_control_is_a_separate_completed_scope_not_a_safe_verdict(self) -> None:
        _context, run, evidence = self.evidence_for("safe")
        self.assertEqual(run.status, "completed")
        self.assertEqual(run.findings, ())
        self.assertEqual(evidence["evidence_class"], "safe")
        self.assertEqual(evidence["finding_bindings"], [])
        self.assertEqual(
            evidence["scope"]["coverage_interpretation"],
            "analyzed_selected_scope_only",
        )
        self.assertEqual(evidence["scope"]["benchmark_outcome"], "not_assigned")
        self.assertTrue(
            any("completed covers only" in item for item in evidence["limitations"])
        )
        self.assertTrue(
            any("not a safe verdict" in item for item in evidence["limitations"])
        )

    def test_partial_failed_and_not_run_are_unknown_and_never_miss(self) -> None:
        context, run, evidence = self.evidence_for("unknown")
        self.assertEqual(run.status, "blocked")
        self.assertEqual(evidence["evidence_class"], "unknown")
        self.assertEqual(
            evidence["scope"]["coverage_interpretation"],
            "unknown_incomplete_analysis",
        )
        self.assertEqual(evidence["scope"]["benchmark_outcome"], "not_assigned")
        statuses = {item.parse_status for item in context.units}
        self.assertEqual(statuses, {"partial", "failed", "not_run", "complete"})
        self.assertTrue(any("parse_status=partial" in item for item in run.limitations))
        self.assertTrue(any("parse_status=failed" in item for item in run.limitations))
        self.assertTrue(any("parse_status=not_run" in item for item in run.limitations))

    def test_missing_symbol_is_unknown_not_completed_or_safe(self) -> None:
        unit = self.by_path[
            "tests/detectors/fixtures/cpp_lifetime/missing_symbol_unresolved_alias.cpp"
        ]
        context = ScanContext(
            request=ScanRequest(
                request_id="test-review:missing-symbol",
                repository=self.manifest["provenance"]["repository"],
                commit=self.manifest["provenance"]["commit"],
                snapshot_sha256=snapshot_digest((unit,)),
                target_id="current-component:" + self.manifest["provenance"]["repository"],
                profile_id=self.manifest["provenance"]["profile_id"],
                provenance="fixture",
            ),
            units=(unit,),
        )
        run = LifetimeOwnershipGuardDetector().detect(context, context.units)
        evidence = build_cpp_lifetime_review_evidence(
            context, run, self.manifest, self.manifest_sha256
        )
        self.assertEqual(run.status, "blocked")
        self.assertEqual(run.findings, ())
        self.assertEqual(
            evidence["scope"]["coverage_interpretation"],
            "unknown_unresolved_rule_symbols",
        )
        self.assertEqual(evidence["scope"]["benchmark_outcome"], "not_assigned")
        self.assertTrue(
            any("Unresolved rule symbols" in item for item in run.limitations)
        )

    def test_incomplete_scope_is_unknown_not_completed_or_safe(self) -> None:
        unit = self.by_path[
            "tests/detectors/fixtures/cpp_lifetime/incomplete_scope_unmodeled_owner.cpp"
        ]
        context = ScanContext(
            request=ScanRequest(
                request_id="test-review:incomplete-scope",
                repository=self.manifest["provenance"]["repository"],
                commit=self.manifest["provenance"]["commit"],
                snapshot_sha256=snapshot_digest((unit,)),
                target_id="current-component:" + self.manifest["provenance"]["repository"],
                profile_id=self.manifest["provenance"]["profile_id"],
                provenance="fixture",
            ),
            units=(unit,),
        )
        run = LifetimeOwnershipGuardDetector().detect(context, context.units)
        evidence = build_cpp_lifetime_review_evidence(
            context, run, self.manifest, self.manifest_sha256
        )
        self.assertEqual(run.status, "blocked")
        self.assertEqual(run.findings, ())
        self.assertEqual(
            evidence["scope"]["coverage_interpretation"],
            "unknown_incomplete_analysis",
        )
        self.assertEqual(evidence["scope"]["benchmark_outcome"], "not_assigned")
        self.assertTrue(
            any(
                "outside a modeled block/function span" in item
                for item in run.limitations
            )
        )

    def test_review_rejects_abnormal_locations_and_metadata(self) -> None:
        context, _run, evidence = self.evidence_for("vulnerable")
        evidence["finding_bindings"][0]["line"] = 0
        with self.assertRaisesRegex(ValueError, "finding line is outside source"):
            verify_review_evidence(evidence, context)

        _context, _run, evidence = self.evidence_for("vulnerable")
        evidence["finding_bindings"][0]["column"] = 10**6
        with self.assertRaisesRegex(ValueError, "finding column is outside source line"):
            verify_review_evidence(evidence, context)

        _context, _run, evidence = self.evidence_for("vulnerable")
        evidence["source_artifacts"][0] = "not-an-object"
        with self.assertRaisesRegex(ValueError, "source artifact metadata must be objects"):
            verify_review_evidence(evidence, context)

    def test_no_matching_language_is_not_applicable_not_miss(self) -> None:
        context = self.context_for("not_applicable")
        registry = DetectorRegistry()
        registry.register(LifetimeOwnershipGuardDetector())
        result = run_all(context, registry)[0]
        self.assertEqual(context.units[0].language, "js")
        self.assertEqual(result.status, "blocked")
        self.assertEqual(result.scope_files, 0)
        self.assertEqual(result.diagnostic_count, 0)
        self.assertTrue(
            any(
                item == "not_applicable: no source with supported language."
                for item in result.limitations
            )
        )
        self.assertFalse(any("miss" in item.lower() for item in result.limitations))

    def test_vulnerable_fixed_unrelated_and_safe_groups_cannot_mix(self) -> None:
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
        run = LifetimeOwnershipGuardDetector().detect(context, context.units)
        with self.assertRaisesRegex(ValueError, "cannot be mixed"):
            build_cpp_lifetime_review_evidence(
                context, run, self.manifest, self.manifest_sha256
            )

    def test_review_rejects_request_tool_scope_and_semantic_tampering(self) -> None:
        context, _run, evidence = self.evidence_for("vulnerable")
        evidence["request"]["commit"] = "f" * 40
        with self.assertRaisesRegex(ValueError, "request binding mismatch"):
            verify_review_evidence(evidence, context)

        _context, _run, evidence = self.evidence_for("vulnerable")
        evidence["tool"]["version"] = "unexpected"
        with self.assertRaisesRegex(ValueError, "tool binding mismatch"):
            verify_review_evidence(evidence, context)

        _context, _run, evidence = self.evidence_for("vulnerable")
        evidence["scope"]["requested_files"] = []
        with self.assertRaisesRegex(ValueError, "requested scope mismatch"):
            verify_review_evidence(evidence, context)

        _context, _run, evidence = self.evidence_for("vulnerable")
        evidence["scope"]["coverage_interpretation"] = (
            "analyzed_selected_scope_only"
        )
        evidence["scope"]["run_status"] = "failed"
        with self.assertRaisesRegex(
            ValueError, "coverage interpretation mismatch"
        ):
            verify_review_evidence(evidence, context)

        _context, _run, evidence = self.evidence_for("vulnerable")
        evidence["scope"]["benchmark_outcome"] = "assigned"
        with self.assertRaisesRegex(
            ValueError, "benchmark outcome must remain not assigned"
        ):
            verify_review_evidence(evidence, context)

    def test_review_rejects_stale_source_hash(self) -> None:
        context, _run, evidence = self.evidence_for("vulnerable")
        evidence["source_artifacts"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "stale review source hash"):
            verify_review_evidence(evidence, context)

    def test_review_rejects_edited_finding_binding_identity(self) -> None:
        context, _run, evidence = self.evidence_for("vulnerable")
        evidence["finding_bindings"][0]["finding_binding_id"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "finding binding identity mismatch"):
            verify_review_evidence(evidence, context)

    def test_invalid_manifest_hash_and_invalid_source_hash_are_rejected(self) -> None:
        context = self.context_for("vulnerable")
        run = LifetimeOwnershipGuardDetector().detect(context, context.units)
        with self.assertRaisesRegex(ValueError, "manifest hash"):
            build_cpp_lifetime_review_evidence(
                context, run, self.manifest, "not-a-sha256"
            )
        with self.assertRaisesRegex(ValueError, "source content hash mismatch"):
            SourceUnit(
                path="tests/detectors/fixtures/cpp_lifetime/generated_invalid.cpp",
                language="cpp",
                text="int main() {}\n",
                sha256="0" * 64,
                parse_status="complete",
            )


if __name__ == "__main__":
    unittest.main()
