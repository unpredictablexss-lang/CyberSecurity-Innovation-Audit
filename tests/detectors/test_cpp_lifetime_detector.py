from __future__ import annotations

import hashlib
import unittest

from src.ohscanner.contracts import SourceUnit
from src.ohscanner.detectors.cpp.lifetime_detector import (
    LifetimeAnalysisOptions,
    LifetimeOwnershipGuardDetector,
)
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

    def generated_unit(self, name: str, text: str) -> SourceUnit:
        return SourceUnit(
            path=f"tests/detectors/fixtures/cpp_lifetime/generated_{name}.cpp",
            language="cpp",
            text=text,
            sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
            parse_status="complete",
        )

    def test_declares_exact_scope_and_required_facts(self) -> None:
        self.assertEqual(self.detector.detector_id, "ohscanner.cpp.lifetime")
        self.assertEqual(self.detector.version, "0.1.0-proposed")
        self.assertEqual(self.detector.supported_languages, ("cpp",))
        self.assertEqual(self.detector.required_facts, ())
        self.assertEqual(self.context.shared_facts, {})

    def test_vulnerable_shape_emits_only_candidate_evidence(self) -> None:
        unit = unit_by_path(self.units, "vulnerable_unserialized.cpp")
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(run.analyzed_files, (unit.path,))
        self.assertEqual(len(run.findings), 1)
        candidate = run.findings[0]
        self.assertEqual(candidate.evidence_type, "syntax")
        self.assertEqual(candidate.candidate_cwe, "CWE-416")
        self.assertEqual(candidate.symbol, "alias")
        self.assertEqual(candidate.rule_id, "ohcpp-lifetime-unique-raw-alias-reset-001")
        self.assertGreater(candidate.line, 0)
        self.assertIn(
            "without a later unconditional straight-line 'alias = owner.get()' rebinding",
            candidate.message,
        )
        self.assertIn("not proof of UAF", candidate.message)
        self.assertTrue(any("not proof of safety" in item for item in run.limitations))

    def test_mutex_scope_is_recorded_without_suppressing_candidate(self) -> None:
        unit = unit_by_path(self.units, "vulnerable_inside_mutex.cpp")
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(len(run.findings), 1)
        self.assertIn("sync_scope=same_scoped_mutex_lock", run.findings[0].message)
        self.assertTrue(any("does not preserve" in item for item in run.limitations))

    def test_fixed_rebind_and_safe_control_have_no_findings(self) -> None:
        fixed = unit_by_path(self.units, "fixed_alias_rebind.cpp")
        safe = unit_by_path(self.units, "safe_use_before_reset.cpp")
        shadowed = unit_by_path(self.units, "safe_shadowed_scope_bindings.cpp")
        for unit in (fixed, safe, shadowed):
            with self.subTest(unit=unit.path):
                run = self.detector.detect(self.context, (unit,))
                self.assertEqual(run.status, "completed")
                self.assertEqual(run.findings, ())
                self.assertEqual(run.analyzed_files, (unit.path,))

    def test_partial_and_failed_parse_are_blocked_unknown_not_completed(self) -> None:
        partial = unit_by_path(self.units, "partial_parse_macro_context.cpp")
        failed = unit_by_path(self.units, "failed_parse_unbalanced.cpp")
        run = self.detector.detect(self.context, (partial, failed))
        self.assertEqual(run.status, "blocked")
        self.assertEqual(run.findings, ())
        self.assertEqual(run.analyzed_files, ())
        self.assertTrue(any("parse_status=partial" in item for item in run.limitations))
        self.assertTrue(any("parse_status=failed" in item for item in run.limitations))
        self.assertTrue(any("remains unknown" in item for item in run.limitations))

    def test_mixed_coverage_analyzes_complete_units_but_stays_blocked(self) -> None:
        complete = unit_by_path(self.units, "vulnerable_unserialized.cpp")
        partial = unit_by_path(self.units, "partial_parse_macro_context.cpp")
        run = self.detector.detect(self.context, (partial, complete))
        self.assertEqual(run.status, "blocked")
        self.assertEqual(run.analyzed_files, (complete.path,))
        self.assertEqual(len(run.findings), 1)

    def test_output_is_stable_and_input_units_are_deduplicated(self) -> None:
        first = self.detector.detect(self.context, tuple(reversed(self.units)))
        second = self.detector.detect(self.context, self.units)
        self.assertEqual(
            tuple((item.file, item.line, item.rule_id, item.message) for item in first.findings),
            tuple((item.file, item.line, item.rule_id, item.message) for item in second.findings),
        )
        vulnerable = unit_by_path(self.units, "vulnerable_unserialized.cpp")
        duplicate_run = self.detector.detect(self.context, (vulnerable, vulnerable))
        self.assertEqual(duplicate_run.analyzed_files, (vulnerable.path,))
        self.assertEqual(len(duplicate_run.findings), 1)

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
        unit = SourceUnit(
            path="tests/detectors/fixtures/cpp_lifetime/generated_parenthesized_alias.cpp",
            language="cpp",
            text=text,
            sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
            parse_status="complete",
        )
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(len(run.findings), 1)
        self.assertEqual(run.findings[0].symbol, "alias")

    def test_nested_use_of_outer_alias_remains_candidate(self) -> None:
        text = """
struct Widget { void Use() const {} };
void nested_outer_alias() {
    std::unique_ptr<Widget> owner;
    Widget* alias = owner.get();
    owner.reset();
    {
        alias->Use();
    }
}
"""
        unit = SourceUnit(
            path="tests/detectors/fixtures/cpp_lifetime/generated_nested_outer_alias.cpp",
            language="cpp",
            text=text,
            sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
            parse_status="complete",
        )
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(len(run.findings), 1)
        self.assertEqual(run.findings[0].symbol, "alias")

    def test_non_owner_pointer_shadowing_is_distinct_binding(self) -> None:
        unit = self.generated_unit(
            "non_owner_pointer_shadowing",
            """
struct Widget { void Use() const {} };
void non_owner_pointer_shadowing(Widget* other) {
    std::unique_ptr<Widget> owner;
    Widget* alias = owner.get();
    owner.reset();
    {
        Widget* alias = other;
        alias->Use();
    }
}
""",
        )
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(run.findings, ())

    def test_unbraced_conditional_rebinding_remains_candidate(self) -> None:
        unit = self.generated_unit(
            "unbraced_conditional_rebind",
            """
struct Widget { void Use() const {} };
void unbraced_conditional_rebind(bool enabled) {
    std::unique_ptr<Widget> owner;
    Widget* alias = owner.get();
    owner.reset();
    if (enabled) alias = owner.get();
    alias->Use();
}
""",
        )
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(len(run.findings), 1)
        self.assertIn(
            "conditional_or_non_straight_line_alias_rebinding_not_suppressed_without_cfg",
            run.findings[0].message,
        )

    def test_rebinding_after_use_does_not_suppress_earlier_candidate(self) -> None:
        unit = self.generated_unit(
            "late_rebind_after_use",
            """
struct Widget { void Use() const {} };
void late_rebind_after_use() {
    std::unique_ptr<Widget> owner;
    Widget* alias = owner.get();
    owner.reset();
    alias->Use();
    alias = owner.get();
}
""",
        )
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(len(run.findings), 1)
        self.assertEqual(run.findings[0].symbol, "alias")

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
        unit = SourceUnit(
            path="tests/detectors/fixtures/cpp_lifetime/generated_comment_only.cpp",
            language="cpp",
            text=text,
            sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
            parse_status="complete",
        )
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.findings, ())

    def test_rebound_alias_suppression_is_explicit_ablation(self) -> None:
        fixed = unit_by_path(self.units, "fixed_alias_rebind.cpp")
        base = LifetimeOwnershipGuardDetector(
            LifetimeAnalysisOptions(suppress_rebound_alias=False, classify_sync_scope=False)
        ).detect(self.context, (fixed,))
        complete = self.detector.detect(self.context, (fixed,))
        self.assertEqual(len(base.findings), 1)
        self.assertIn("alias_rebinding_observed_but_not_suppressed_by_ablation", base.findings[0].message)
        self.assertEqual(complete.findings, ())

    def test_conditional_rebinding_is_not_suppressed_without_cfg(self) -> None:
        unit = unit_by_path(self.units, "vulnerable_conditional_rebind.cpp")
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(len(run.findings), 1)
        self.assertIn(
            "conditional_or_non_straight_line_alias_rebinding_not_suppressed_without_cfg",
            run.findings[0].message,
        )

    def test_cooperative_timeout_fails_only_this_detector_run(self) -> None:
        vulnerable = unit_by_path(self.units, "vulnerable_unserialized.cpp")
        detector = LifetimeOwnershipGuardDetector(
            LifetimeAnalysisOptions(timeout_check=lambda: True)
        )
        run = detector.detect(self.context, (vulnerable,))
        self.assertEqual(run.status, "failed")
        self.assertEqual(run.findings, ())
        self.assertEqual(run.analyzed_files, ())
        self.assertTrue(any("Cooperative timeout" in item for item in run.limitations))


if __name__ == "__main__":
    unittest.main()
