from __future__ import annotations

import dataclasses
import hashlib
import unittest

from src.ohscanner.detectors.cpp.lifetime_detector import (
    LifetimeAnalysisOptions,
    LifetimeOwnershipGuardDetector,
)
from src.ohscanner.detectors.cpp.proposed_contract import ProposedSourceUnit
from tests.detectors.fixture_support import (
    lifetime_context,
    load_lifetime_units,
    unit_by_path,
)


class LifetimeDetectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.units = load_lifetime_units()
        self.context = lifetime_context()
        self.detector = LifetimeOwnershipGuardDetector()

    def test_declares_exact_proposed_scope_and_required_facts(self) -> None:
        self.assertEqual(self.detector.detector_id, "ohscanner.cpp.lifetime")
        self.assertEqual(self.detector.version, "0.1.0-proposed")
        self.assertEqual(self.detector.supported_languages, ("cpp",))
        self.assertEqual(
            self.detector.required_facts,
            (
                "repository_commit_profile_provenance",
                "source_path",
                "source_text",
                "source_sha256",
                "parse_status",
            ),
        )

    def test_vulnerable_shape_emits_only_unassessed_candidate(self) -> None:
        unit = unit_by_path(self.units, "vulnerable_unserialized.cpp")
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(len(run.diagnostics), 1)
        candidate = run.diagnostics[0]
        self.assertEqual(candidate.evidence_type, "syntax")
        self.assertEqual(candidate.candidate_cwe, "CWE-416")
        self.assertEqual(candidate.severity, "unassessed")
        self.assertEqual(candidate.confidence, "unassessed")
        self.assertGreater(candidate.line, 0)
        self.assertIn("before a new owner.get() binding", candidate.explanation)
        sidecar = candidate.sidecar_dict()
        self.assertEqual(sidecar["candidate_status"], "candidate")
        self.assertEqual(sidecar["review_status"], "unassessed")
        self.assertEqual(sidecar["validation_status"], "not_run")
        self.assertNotIn("confirmed", sidecar)

    def test_mutex_scope_is_recorded_without_suppressing_candidate(self) -> None:
        unit = unit_by_path(self.units, "vulnerable_inside_mutex.cpp")
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(len(run.diagnostics), 1)
        self.assertIn(
            "sync_scope=same_scoped_mutex_lock",
            run.diagnostics[0].constraints,
        )
        self.assertTrue(
            any("does not preserve" in item for item in run.diagnostics[0].limitations)
        )

    def test_fixed_rebind_and_safe_control_have_no_diagnostics(self) -> None:
        fixed = unit_by_path(self.units, "fixed_alias_rebind.cpp")
        safe = unit_by_path(self.units, "safe_use_before_reset.cpp")
        for unit in (fixed, safe):
            with self.subTest(unit=unit.path):
                run = self.detector.detect(self.context, (unit,))
                self.assertEqual(run.status, "completed")
                self.assertEqual(run.diagnostics, ())
                self.assertEqual(run.analyzed_files, (unit.path,))
                self.assertNotIn("safe", (item.message for item in run.diagnostics))

    def test_partial_and_failed_parse_keep_coverage_and_unknown_limitation(self) -> None:
        partial = unit_by_path(self.units, "partial_parse_macro_context.cpp")
        failed = unit_by_path(self.units, "failed_parse_unbalanced.cpp")
        run = self.detector.detect(self.context, (partial, failed))
        self.assertEqual(run.status, "completed")
        self.assertEqual(run.diagnostics, ())
        self.assertEqual(run.analyzed_files, ())
        coverage = {item.file: item for item in run.coverage}
        self.assertEqual(coverage[partial.path].parse_status, "partial")
        self.assertEqual(coverage[failed.path].parse_status, "failed")
        self.assertFalse(coverage[partial.path].analyzed)
        self.assertFalse(coverage[failed.path].analyzed)
        self.assertTrue(any("remains unknown" in item for item in run.limitations))
        self.assertTrue(any("empty diagnostics" in item for item in run.limitations))
        self.assertTrue(any("not proof of safety" in item for item in run.limitations))

    def test_output_is_stable_and_duplicate_ids_are_collapsed(self) -> None:
        first = self.detector.detect(self.context, tuple(reversed(self.units)))
        second = self.detector.detect(self.context, self.units)
        self.assertEqual(
            tuple(item.diagnostic_id for item in first.diagnostics),
            tuple(item.diagnostic_id for item in second.diagnostics),
        )
        vulnerable = unit_by_path(self.units, "vulnerable_unserialized.cpp")
        duplicate_run = self.detector.detect(self.context, (vulnerable, vulnerable))
        self.assertEqual(len(duplicate_run.diagnostics), 1)

    def test_bad_source_hash_fails_input_but_does_not_hide_valid_unit(self) -> None:
        valid = unit_by_path(self.units, "vulnerable_unserialized.cpp")
        bad = dataclasses.replace(valid, text=valid.text.replace("Widget", "Widget2", 1))
        run = self.detector.detect(self.context, (valid, bad))
        self.assertEqual(run.status, "failed")
        self.assertEqual(run.failure_kind, "input_validation")
        self.assertEqual(len(run.diagnostics), 1)
        self.assertEqual(run.diagnostics[0].file, valid.path)
        self.assertTrue(any("sha256 does not match" in item for item in run.limitations))

    def test_invalid_request_provenance_fails_closed_without_candidates(self) -> None:
        request = dataclasses.replace(self.context.request, commit="not-a-sha")
        context = dataclasses.replace(self.context, request=request)
        run = self.detector.detect(context, (self.units[0],))
        self.assertEqual(run.status, "failed")
        self.assertEqual(run.failure_kind, "input_validation")
        self.assertEqual(run.diagnostics, ())
        self.assertEqual(run.analyzed_files, ())
        self.assertTrue(any("request.commit" in item for item in run.limitations))

    def test_parenthesized_alias_dereference_is_one_candidate(self) -> None:
        text = """
#include <memory>
struct Widget { int Value() const { return 1; } };
void consume(int) {}
void parenthesized_alias() {
    std::unique_ptr<Widget> owner = std::make_unique<Widget>();
    Widget* alias = owner.get();
    owner.reset();
    consume((*alias).Value());
}
"""
        unit = ProposedSourceUnit(
            path="tests/detectors/fixtures/cpp_lifetime/generated_parenthesized_alias.cpp",
            language="cpp",
            sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
            text=text,
            parse_status="complete",
        )
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(len(run.diagnostics), 1)
        self.assertEqual(run.diagnostics[0].symbol, "alias")

    def test_comments_and_string_literals_are_not_analyzed(self) -> None:
        text = """
void commented() {
    // std::unique_ptr<Widget> owner = std::make_unique<Widget>();
    // Widget* alias = owner.get();
    // owner.reset();
    // consume(alias->Value());
    const char* text = "owner.reset(); alias->Value()";
}
"""
        unit = ProposedSourceUnit(
            path="tests/detectors/fixtures/cpp_lifetime/generated_comment_only.cpp",
            language="cpp",
            sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
            text=text,
            parse_status="complete",
        )
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.diagnostics, ())

    def test_rebound_alias_suppression_is_explicit_ablation(self) -> None:
        fixed = unit_by_path(self.units, "fixed_alias_rebind.cpp")
        base = LifetimeOwnershipGuardDetector(
            LifetimeAnalysisOptions(suppress_rebound_alias=False, classify_sync_scope=False)
        ).detect(self.context, (fixed,))
        complete = self.detector.detect(self.context, (fixed,))
        self.assertEqual(len(base.diagnostics), 1)
        self.assertIn("alias_rebinding_observed_but_not_suppressed_by_ablation", base.diagnostics[0].constraints)
        self.assertEqual(complete.diagnostics, ())


if __name__ == "__main__":
    unittest.main()
