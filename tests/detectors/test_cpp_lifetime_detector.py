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
        self.assertEqual(self.detector.version, "0.4.0")
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

    def test_owner_null_assignment_invalidates_raw_alias(self) -> None:
        text = """
#include <memory>
struct Widget { void Use() const {} };
void null_assignment() {
    std::unique_ptr<Widget> owner = std::make_unique<Widget>();
    Widget* alias = owner.get();
    owner = nullptr;
    alias->Use();
}
"""
        unit = self.generated_unit("owner_null_assignment", text)
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(len(run.findings), 1)
        self.assertIn("owner assignment", run.findings[0].message)
        self.assertIn("not proof of UAF", run.findings[0].message)

    def test_owner_replacement_invalidates_previous_object(self) -> None:
        text = """
#include <memory>
struct Widget { void Use() const {} };
void owner_replacement() {
    std::unique_ptr<Widget> owner = std::make_unique<Widget>();
    Widget* alias = owner.get();
    owner = std::make_unique<Widget>();
    alias->Use();
}
"""
        unit = self.generated_unit("owner_replacement", text)
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(len(run.findings), 1)
        self.assertIn("owner assignment", run.findings[0].message)

    def test_move_from_owner_invalidates_transferred_object_alias(self) -> None:
        text = """
#include <memory>
#include <utility>
struct Widget { void Use() const {} };
void move_from_owner() {
    std::unique_ptr<Widget> owner = std::make_unique<Widget>();
    Widget* alias = owner.get();
    {
        std::unique_ptr<Widget> next = std::move(owner);
    }
    alias->Use();
}
"""
        unit = self.generated_unit("move_from_owner", text)
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(len(run.findings), 1)
        self.assertIn("move transfer", run.findings[0].message)
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
        self.assertEqual(run.status, "completed")
        self.assertEqual(len(run.findings), 1)
        self.assertEqual(run.findings[0].symbol, "alias")
        self.assertNotIn(
            "alias_escape_or_transfer_coverage_unknown",
            run.findings[0].message,
        )

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

    def test_auto_pointer_shadowing_is_distinct_binding(self) -> None:
        unit = self.generated_unit(
            "auto_pointer_shadowing",
            """
struct Widget { void Use() const {} };
void auto_pointer_shadowing(Widget* other) {
    std::unique_ptr<Widget> owner;
    Widget* alias = owner.get();
    owner.reset();
    {
        auto alias = other;
        alias->Use();
    }
}
""",
        )
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(run.findings, ())

    def test_auto_shadow_is_scoped_to_its_block(self) -> None:
        unit = self.generated_unit(
            "auto_shadow_scope_boundary",
            """
struct Widget { void Use() const {} };
void auto_shadow_scope_boundary(Widget* other) {
    std::unique_ptr<Widget> owner;
    Widget* alias = owner.get();
    owner.reset();
    {
        auto alias = other;
        alias->Use();
    }
    alias->Use();
}
""",
        )
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(len(run.findings), 1)
        self.assertEqual(run.findings[0].symbol, "alias")

    def test_auto_shadow_after_use_does_not_suppress_earlier_candidate(self) -> None:
        unit = self.generated_unit(
            "auto_shadow_after_use",
            """
struct Widget { void Use() const {} };
void auto_shadow_after_use(Widget* other) {
    std::unique_ptr<Widget> owner;
    Widget* alias = owner.get();
    owner.reset();
    alias->Use();
    {
        auto alias = other;
        alias->Use();
    }
}
""",
        )
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(len(run.findings), 1)
        self.assertEqual(run.findings[0].symbol, "alias")

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

    def test_same_name_owner_and_alias_bindings_do_not_cross_functions(self) -> None:
        unit = self.generated_unit(
            "same_name_disjoint_functions",
            """
struct Widget { void Use() const {} };
void first_same_name_scope() {
    std::unique_ptr<Widget> owner;
    Widget* alias = owner.get();
    owner.reset();
    alias->Use();
}
void second_same_name_scope() {
    std::unique_ptr<Widget> owner;
    Widget* alias = owner.get();
    alias->Use();
    owner.reset();
}
""",
        )
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(len(run.findings), 1)
        self.assertIn("first_same_name_scope", run.findings[0].message)
        self.assertRegex(
            run.findings[0].message,
            r"lexical_binding_identity=owner-[a-f0-9]{12}:alias-[a-f0-9]{12}",
        )

    def test_duplicate_class_declarations_are_isolated_across_source_units(self) -> None:
        first = self.generated_unit(
            "duplicate_class_first",
            """
class Holder { public: void Use() const {} };
void run_case() {
    std::unique_ptr<Holder> owner = std::make_unique<Holder>();
    Holder* alias = owner.get();
    owner.reset();
    alias->Use();
}
// first distinct source bytes
""",
        )
        second = self.generated_unit(
            "duplicate_class_second",
            """
class Holder { public: void Use() const {} };
void run_case() {
    std::unique_ptr<Holder> owner = std::make_unique<Holder>();
    Holder* alias = owner.get();
    owner.reset();
    alias->Use();
}
// second distinct source bytes
""",
        )
        run = self.detector.detect(self.context, (first, second))
        self.assertEqual(run.status, "completed")
        self.assertEqual(run.analyzed_files, (first.path, second.path))
        self.assertEqual(len(run.findings), 2)
        self.assertEqual(
            {(item.file, item.source_sha256) for item in run.findings},
            {
                (first.path, first.sha256),
                (second.path, second.sha256),
            },
        )

    def test_member_assignment_does_not_rebind_a_local_alias(self) -> None:
        unit = self.generated_unit(
            "member_assignment_not_local_rebind",
            """
struct Holder { Widget* alias = nullptr; };
struct Widget { void Use() const {} };
void member_assignment_not_local_rebind(Holder& holder) {
    std::unique_ptr<Widget> owner;
    Widget* alias = owner.get();
    owner.reset();
    holder.alias = owner.get();
    alias->Use();
}
""",
        )
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "blocked")
        self.assertEqual(len(run.findings), 1)
        self.assertEqual(run.findings[0].symbol, "alias")
        self.assertTrue(
            any("Member-access owner.get() storage" in item for item in run.limitations)
        )

    def test_member_alias_only_is_unknown_and_not_a_local_binding(self) -> None:
        unit = self.generated_unit(
            "member_alias_only",
            """
struct Holder { Widget* alias = nullptr; };
struct Widget { void Use() const {} };
void member_alias_only(Holder& holder) {
    std::unique_ptr<Widget> owner;
    owner.reset();
    holder.alias = owner.get();
    holder.alias->Use();
}
""",
        )
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "blocked")
        self.assertEqual(run.findings, ())
        self.assertTrue(
            any("remain unknown" in item for item in run.limitations)
        )

    def test_lambda_capture_escape_is_unknown_but_not_safe(self) -> None:
        unit = self.generated_unit(
            "lambda_capture_escape",
            """
struct Widget { void Use() const {} };
void lambda_capture_escape() {
    std::unique_ptr<Widget> owner;
    Widget* alias = owner.get();
    auto callback = [alias]() { return alias != nullptr; };
    owner.reset();
    (void)callback;
}
""",
        )
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "blocked")
        self.assertEqual(run.findings, ())
        self.assertTrue(any("lambda_capture" in item for item in run.limitations))
        self.assertTrue(any("not treated as safe" in item for item in run.limitations))

    def test_cross_function_escape_keeps_observed_candidate_and_marks_unknown(self) -> None:
        unit = self.generated_unit(
            "cross_function_escape",
            """
struct Widget { void Use() const {} };
void consume(Widget* value) { (void)value; }
void cross_function_escape() {
    std::unique_ptr<Widget> owner;
    Widget* alias = owner.get();
    consume(alias);
    owner.reset();
    alias->Use();
}
""",
        )
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "blocked")
        self.assertEqual(len(run.findings), 1)
        self.assertIn(
            "alias_escape_or_transfer_coverage_unknown",
            run.findings[0].message,
        )
        self.assertTrue(
            any("cross_function_call:consume" in item for item in run.limitations)
        )

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


    def test_alias_assignment_from_owner_is_modeled(self) -> None:
        text = """
#include <memory>
struct Widget { void Use() const {} };
void alias_assignment() {
    std::unique_ptr<Widget> owner = std::make_unique<Widget>();
    Widget* alias = nullptr;
    alias = owner.get();
    owner.reset();
    alias->Use();
}
"""
        unit = self.generated_unit("alias_assignment", text)
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(len(run.findings), 1)
        self.assertEqual(run.findings[0].symbol, "alias")
        self.assertIn("reset", run.findings[0].message)

    def test_intra_function_alias_chain_is_modeled(self) -> None:
        text = """
#include <memory>
struct Widget { void Use() const {} };
void alias_chain() {
    std::unique_ptr<Widget> owner = std::make_unique<Widget>();
    Widget* alias = owner.get();
    Widget* use_alias = alias;
    owner.reset();
    use_alias->Use();
}
"""
        unit = self.generated_unit("alias_chain", text)
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(len(run.findings), 1)
        self.assertEqual(run.findings[0].symbol, "use_alias")

    def test_mutually_exclusive_branch_pair_is_not_reported(self) -> None:
        text = """
#include <memory>
struct Widget { void Use() const {} };
void branch_exclusion(bool reset_owner) {
    std::unique_ptr<Widget> owner = std::make_unique<Widget>();
    Widget* alias = owner.get();
    if (reset_owner) {
        owner.reset();
    } else {
        alias->Use();
    }
}
"""
        unit = self.generated_unit("branch_exclusion", text)
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(run.findings, ())
        self.assertTrue(
            any("mutually exclusive narrow CFG branches" in item for item in run.limitations)
        )

    def test_owner_scope_end_invalidates_outer_alias(self) -> None:
        text = """
#include <memory>
struct Widget { void Use() const {} };
void owner_scope_end() {
    Widget* alias = nullptr;
    {
        std::unique_ptr<Widget> owner = std::make_unique<Widget>();
        alias = owner.get();
    }
    alias->Use();
}
"""
        unit = self.generated_unit("owner_scope_end", text)
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(len(run.findings), 1)
        self.assertIn("owner scope end", run.findings[0].message)

    def test_owner_scope_boundary_control_is_not_reported(self) -> None:
        text = """
#include <memory>
struct Widget { void Use() const {} };
void owner_alive_at_use() {
    std::unique_ptr<Widget> owner = std::make_unique<Widget>();
    Widget* alias = nullptr;
    {
        alias = owner.get();
    }
    alias->Use();
}
"""
        unit = self.generated_unit("owner_alive_at_use", text)
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(run.findings, ())


if __name__ == "__main__":
    unittest.main()
