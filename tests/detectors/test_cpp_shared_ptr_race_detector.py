from __future__ import annotations

import hashlib
import unittest

from src.ohscanner.contracts import DetectorRun, ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.cpp.shared_ptr_race_detector import (
    SharedPtrRaceDetector,
)
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.runner import DetectorRegistry, run_all
from tests.detectors.shared_ptr_race_fixture_support import (
    load_shared_ptr_race_units,
    shared_ptr_race_context,
    unit_by_path,
)


class _CrashingDetector:
    detector_id = "ohscanner.test.shared-ptr-race-crash"
    version = "0.0.1"
    supported_languages = ("cpp",)
    required_facts = ()

    def detect(self, context, units):
        del context, units
        raise RuntimeError("synthetic detector crash")


class SharedPtrRaceDetectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.units = load_shared_ptr_race_units()
        self.context = shared_ptr_race_context()
        self.detector = SharedPtrRaceDetector()

    def generated_unit(self, name: str, text: str) -> SourceUnit:
        return SourceUnit(
            path=f"tests/detectors/fixtures/cpp_shared_ptr_race/generated_{name}.cpp",
            language="cpp",
            text=text,
            sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
            parse_status="complete",
        )

    def test_declares_exact_scope_and_required_facts(self) -> None:
        self.assertEqual(self.detector.detector_id, "ohscanner.cpp.shared_ptr_race")
        self.assertEqual(self.detector.version, "0.1.0-proposed")
        self.assertEqual(self.detector.supported_languages, ("cpp",))
        self.assertEqual(self.detector.required_facts, ())

    def test_vulnerable_shape_emits_only_candidate_evidence(self) -> None:
        unit = unit_by_path(self.units, "vulnerable_non_atomic_shared_ptr.cpp")
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(run.analyzed_files, (unit.path,))
        self.assertGreater(len(run.findings), 0)
        for finding in run.findings:
            self.assertEqual(finding.evidence_type, "syntax")
            self.assertEqual(finding.candidate_cwe, "CWE-362")
            self.assertEqual(finding.symbol, "instance_")
            self.assertEqual(
                finding.rule_id,
                "ohcpp-shared-ptr-race-candidate-001",
            )
            self.assertIn("Candidate only:", finding.message)
            self.assertIn("CWE-416/use-after-free is only a possible consequence", finding.message)
            self.assertIn("does not prove UAF", finding.message)
            self.assertIn("guard dominance", finding.message)
            self.assertIn("concurrent interleaving", finding.message)
            self.assertIn("attacker control", finding.message)
            self.assertIn("security impact", finding.message)
        self.assertTrue(
            any("completed covers only" in item for item in run.limitations)
        )

    def test_fixed_and_safe_shapes_have_no_findings(self) -> None:
        fixed = unit_by_path(self.units, "fixed_atomic_shared_ptr.cpp")
        safe = unit_by_path(self.units, "safe_atomic_only.cpp")
        for unit in (fixed, safe):
            with self.subTest(unit=unit.path):
                run = self.detector.detect(self.context, (unit,))
                self.assertEqual(run.status, "completed")
                self.assertEqual(run.findings, ())
                self.assertEqual(run.analyzed_files, (unit.path,))

    def test_unrelated_shape_has_no_findings(self) -> None:
        unit = unit_by_path(self.units, "unrelated_plain_pointer.cpp")
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(run.findings, ())
        self.assertEqual(run.analyzed_files, (unit.path,))

    def test_partial_failed_and_not_run_are_blocked_unknown(self) -> None:
        partial = unit_by_path(self.units, "unknown_partial_parse.cpp")
        failed = unit_by_path(self.units, "unknown_failed_parse.cpp")
        not_run = unit_by_path(self.units, "unknown_not_run.cpp")
        run = self.detector.detect(self.context, (partial, failed, not_run))
        self.assertEqual(run.status, "blocked")
        self.assertEqual(run.findings, ())
        self.assertEqual(run.analyzed_files, ())
        self.assertTrue(any("parse_status=partial" in item for item in run.limitations))
        self.assertTrue(any("parse_status=failed" in item for item in run.limitations))
        self.assertTrue(any("parse_status=not_run" in item for item in run.limitations))

    def test_mixed_coverage_analyzes_complete_units_but_stays_blocked(self) -> None:
        complete = unit_by_path(self.units, "vulnerable_non_atomic_shared_ptr.cpp")
        partial = unit_by_path(self.units, "unknown_partial_parse.cpp")
        run = self.detector.detect(self.context, (partial, complete))
        self.assertEqual(run.status, "blocked")
        self.assertEqual(run.analyzed_files, (complete.path,))
        self.assertGreater(len(run.findings), 0)

    def test_incomplete_scope_is_blocked_unknown_not_safe(self) -> None:
        unit = unit_by_path(self.units, "unknown_incomplete_scope.cpp")
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "blocked")
        self.assertEqual(run.findings, ())
        self.assertTrue(
            any("outside a modeled function span" in item for item in run.limitations)
        )

    def test_no_matching_language_is_not_applicable_not_miss(self) -> None:
        js = unit_by_path(self.units, "not_applicable_no_matching_language.js")
        provenance = self.context.request
        context = ScanContext(
            request=ScanRequest(
                request_id="test-shared-ptr-race:not-applicable",
                repository=provenance.repository,
                commit=provenance.commit,
                snapshot_sha256=snapshot_digest((js,)),
                target_id=provenance.target_id,
                profile_id=provenance.profile_id,
                provenance="fixture",
            ),
            units=(js,),
        )
        registry = DetectorRegistry()
        registry.register(self.detector)
        result = run_all(context, registry)[0]
        self.assertEqual(js.language, "js")
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

    def test_output_is_stable_and_duplicate_units_are_deduplicated(self) -> None:
        first = self.detector.detect(self.context, tuple(reversed(self.units)))
        second = self.detector.detect(self.context, self.units)
        self.assertEqual(
            tuple(
                (item.file, item.line, item.column, item.rule_id, item.message)
                for item in first.findings
            ),
            tuple(
                (item.file, item.line, item.column, item.rule_id, item.message)
                for item in second.findings
            ),
        )
        vulnerable = unit_by_path(self.units, "vulnerable_non_atomic_shared_ptr.cpp")
        duplicate_run = self.detector.detect(self.context, (vulnerable, vulnerable))
        self.assertEqual(duplicate_run.analyzed_files, (vulnerable.path,))
        self.assertEqual(len(duplicate_run.findings), len(
            self.detector.detect(self.context, (vulnerable,)).findings
        ))

    def test_crash_is_isolated_and_this_detector_still_runs(self) -> None:
        registry = DetectorRegistry()
        registry.register(_CrashingDetector())
        registry.register(self.detector)
        results = run_all(self.context, registry)
        self.assertEqual(
            [item.tool for item in results],
            ["ohscanner.cpp.shared_ptr_race", "ohscanner.test.shared-ptr-race-crash"],
        )
        self.assertEqual(results[0].status, "blocked")
        self.assertEqual(results[1].status, "failed")
        self.assertTrue(
            any("Detector failed: RuntimeError" in item for item in results[1].limitations)
        )

    def test_detector_returns_blocked_when_selected_scope_is_empty(self) -> None:
        run = self.detector.detect(self.context, ())
        self.assertEqual(run.status, "blocked")
        self.assertEqual(run.analyzed_files, ())
        self.assertTrue(
            any("no source with supported language" in item for item in run.limitations)
        )

    def test_comments_and_string_literals_are_not_analyzed(self) -> None:
        text = """
#include <memory>
class Widget { public: int value = 1; };
class Holder {
public:
    static std::shared_ptr<Widget> instance_;
};
std::shared_ptr<Widget> Holder::instance_ = nullptr;
void holder_use() {
    // instance_.reset();
    const char* text = "instance_.reset(); return instance_;";
    (void)text;
}
"""
        unit = self.generated_unit("comment_and_literal_only", text)
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(run.findings, ())

    def test_qualified_static_definition_is_not_a_candidate_access(self) -> None:
        text = """
#include <memory>
class Widget { public: int value = 1; };
class Holder {
public:
    static std::shared_ptr<Widget> instance_;
};
std::shared_ptr<Widget> Holder::instance_ = nullptr;
"""
        unit = self.generated_unit("qualified_static_definition", text)
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(run.findings, ())

    def test_same_member_name_in_another_class_is_not_attributed(self) -> None:
        text = """
#include <memory>
class SharedHolder {
public:
    static std::shared_ptr<int> instance_;
};
class RawHolder {
public:
    static int* instance_;
};
std::shared_ptr<int> SharedHolder::instance_ = nullptr;
int* RawHolder::instance_ = nullptr;
int* RawHolder::Load() { return instance_; }
"""
        unit = self.generated_unit("same_name_other_class", text)
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(run.findings, ())

    def test_std_namespaced_atomic_load_and_store_are_not_findings(self) -> None:
        text = """
#include <atomic>
#include <memory>
class Widget { public: int value = 1; };
class Holder {
public:
    static std::shared_ptr<Widget> instance_;
};
std::shared_ptr<Widget> Holder::instance_ = nullptr;
std::shared_ptr<Widget> Holder::Load() {
    return std::atomic_load(&instance_);
}
void Holder::Clear() {
    std::atomic_store(&instance_, std::shared_ptr<Widget>(nullptr));
}
"""
        unit = self.generated_unit("std_namespaced_atomic_forms", text)
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(run.findings, ())


if __name__ == "__main__":
    unittest.main()
