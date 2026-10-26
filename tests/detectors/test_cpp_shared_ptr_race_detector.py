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
        self.assertEqual(self.detector.version, "0.5.1")
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

    def test_legacy_fixed_mixed_shape_is_candidate_unknown_and_atomic_only_is_safe(self) -> None:
        fixed = unit_by_path(self.units, "fixed_atomic_shared_ptr.cpp")
        safe = unit_by_path(self.units, "safe_atomic_only.cpp")

        fixed_run = self.detector.detect(self.context, (fixed,))
        self.assertEqual(fixed_run.status, "completed")
        self.assertGreater(len(fixed_run.findings), 0)
        self.assertEqual(fixed_run.analyzed_files, (fixed.path,))
        for finding in fixed_run.findings:
            self.assert_synchronization_proof_unknown(finding)

        safe_run = self.detector.detect(self.context, (safe,))
        self.assertEqual(safe_run.status, "completed")
        self.assertEqual(safe_run.findings, ())
        self.assertEqual(safe_run.analyzed_files, (safe.path,))

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


    def test_global_shared_ptr_is_explicitly_not_applicable(self) -> None:
        text = """
#include <memory>
std::shared_ptr<int> instance_;
void use_global() {
    instance_.reset();
}
"""
        unit = self.generated_unit("global_only", text)
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(run.findings, ())
        self.assertTrue(
            any(
                "not_applicable: global shared_ptr declaration 'instance_'" in item
                for item in run.limitations
            )
        )

    def test_global_and_member_same_name_bind_only_the_member_access(self) -> None:
        text = """
#include <memory>
std::shared_ptr<int> instance_;
class Holder {
public:
    static std::shared_ptr<int> instance_;
    static void Reset();
};
std::shared_ptr<int> Holder::instance_ = nullptr;
void use_global() {
    instance_.reset();
}
void Holder::Reset() {
    instance_.reset();
}
"""
        unit = self.generated_unit("global_and_member_same_name", text)
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(len(run.findings), 1)
        self.assertEqual(run.findings[0].symbol, "instance_")
        self.assertGreater(run.findings[0].line, text.splitlines().index("void Holder::Reset() {") + 1)

    def test_namespace_qualified_access_is_bound_to_the_class_member(self) -> None:
        text = """
#include <memory>
namespace sample {
class Holder {
public:
    static std::shared_ptr<int> instance_;
};
std::shared_ptr<int> Holder::instance_ = nullptr;
void touch() {
    Holder::instance_.reset();
}
}
"""
        unit = self.generated_unit("namespace_qualified", text)
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(len(run.findings), 1)
        self.assertIn("instance_", run.findings[0].message)

    def test_templated_class_owner_is_bound_for_out_of_line_method(self) -> None:
        text = """
#include <memory>
namespace sample {
template<typename T>
class Holder {
public:
    static std::shared_ptr<T> instance_;
    static std::shared_ptr<T> Load();
};

template<typename T>
std::shared_ptr<T> Holder<T>::instance_ = nullptr;

template<typename T>
std::shared_ptr<T> Holder<T>::Load()
{
    instance_.reset();
}
}
"""
        unit = self.generated_unit("templated_owner", text)
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(len(run.findings), 1)
        self.assertIn("instance_", run.findings[0].message)
    def test_local_shadowing_does_not_replace_this_member_access(self) -> None:
        text = """
#include <memory>
class Holder {
public:
    static std::shared_ptr<int> instance_;
    void Reset() {
        std::shared_ptr<int> instance_;
        instance_.reset();
        this->instance_.reset();
    }
};
"""
        unit = self.generated_unit("local_shadow", text)
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(len(run.findings), 1)
        self.assertIn("this->instance_", unit.text.splitlines()[run.findings[0].line - 1])

    def test_same_name_in_different_translation_units_is_not_cross_bound(self) -> None:
        text_a = """
#include <memory>
class Holder {
public:
    static std::shared_ptr<int> instance_;
    void Reset() { instance_.reset(); }
};
"""
        text_b = text_a.replace("class Holder", "class Holder")
        first = self.generated_unit("translation_unit_a", text_a)
        second = self.generated_unit("translation_unit_b", text_b)
        run = self.detector.detect(self.context, (first, second))
        self.assertEqual(run.status, "completed")
        self.assertEqual({finding.file for finding in run.findings}, {first.path, second.path})
        self.assertEqual(len(run.findings), 2)
    def test_duplicate_class_declarations_are_not_cross_bound(self) -> None:
        first = self.generated_unit(
            "duplicate_class_write",
            """
#include <memory>
#include <mutex>
class Holder {
public:
    std::shared_ptr<int> instance_;
    std::mutex mutex_;
    void Reset() {
        std::lock_guard<std::mutex> guard(mutex_);
        instance_.reset();
    }
};
""",
        )
        second = self.generated_unit(
            "duplicate_class_read",
            """
#include <memory>
#include <mutex>
class Holder {
public:
    std::shared_ptr<int> instance_;
    std::mutex mutex_;
    int Read() const {
        std::lock_guard<std::mutex> guard(mutex_);
        return instance_ ? 1 : 0;
    }
};
""",
        )
        run = self.detector.detect(self.context, (first, second))
        self.assertEqual(run.status, "completed")
        self.assertEqual(len(run.findings), 1)
        self.assertEqual(run.findings[0].file, first.path)


    def test_unresolved_object_member_access_is_unknown(self) -> None:
        text = """
#include <memory>
class Holder {
public:
    std::shared_ptr<int> instance_;
};
void touch(Holder& holder) {
    holder.instance_.reset();
}
"""
        unit = self.generated_unit("object_access", text)
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "blocked")
        self.assertEqual(run.findings, ())
        self.assertTrue(
            any("unresolved object expression" in item for item in run.limitations)
        )

    def test_all_accesses_under_same_mutex_are_suppressed(self) -> None:
        text = """
#include <memory>
#include <mutex>
class Holder {
public:
    static std::shared_ptr<int> instance_;
    static std::mutex mutex_;
    static void Reset() {
        std::lock_guard<std::mutex> lock(mutex_);
        instance_.reset();
    }
    static int Load() {
        std::lock_guard<std::mutex> lock(mutex_);
        return instance_ ? 1 : 0;
    }
};
"""
        unit = self.generated_unit("same_mutex", text)
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(run.findings, ())
        self.assertTrue(any("share reliable lexical mutex 'mutex_'" in item for item in run.limitations))

    def test_one_sided_mutex_reports_only_unprotected_access(self) -> None:
        text = """
#include <memory>
#include <mutex>
class Holder {
public:
    static std::shared_ptr<int> instance_;
    static std::mutex mutex_;
    static void ResetGuarded() {
        std::lock_guard<std::mutex> lock(mutex_);
        instance_.reset();
    }
    static void ResetUnguarded() {
        instance_.reset();
    }
};
"""
        unit = self.generated_unit("one_sided_mutex", text)
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(len(run.findings), 1)
        self.assertGreater(run.findings[0].line, text.splitlines().index("    static void ResetUnguarded() {") + 1)
        self.assertIn("candidate/unknown", run.findings[0].message)
        self.assert_synchronization_proof_unknown(run.findings[0], "one-sided")

    def test_different_mutexes_do_not_get_suppressed(self) -> None:
        text = """
#include <memory>
#include <mutex>
class Holder {
public:
    static std::shared_ptr<int> instance_;
    static std::mutex mutex_a_;
    static std::mutex mutex_b_;
    static void ResetA() {
        std::lock_guard<std::mutex> lock(mutex_a_);
        instance_.reset();
    }
    static void ResetB() {
        std::lock_guard<std::mutex> lock(mutex_b_);
        instance_.reset();
    }
};
"""
        unit = self.generated_unit("different_mutexes", text)
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(len(run.findings), 2)
        self.assertTrue(any("different or one-sided mutexes" in item for item in run.limitations))
        for finding in run.findings:
            self.assert_synchronization_proof_unknown(finding, "different mutex")

    def test_try_to_lock_is_unknown_and_not_suppressed(self) -> None:
        text = """
#include <memory>
#include <mutex>
class Holder {
public:
    static std::shared_ptr<int> instance_;
    static std::mutex mutex_;
    static void Reset() {
        std::unique_lock<std::mutex> lock(mutex_, std::try_to_lock);
        instance_.reset();
    }
};
"""
        unit = self.generated_unit("try_to_lock", text)
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "blocked")
        self.assertEqual(len(run.findings), 1)
        self.assertIn("candidate/unknown", run.findings[0].message)
        self.assert_synchronization_proof_unknown(run.findings[0], "try_to_lock")
        self.assertTrue(any("try_to_lock does not prove" in item for item in run.limitations))

    def test_defer_lock_is_unknown_and_not_suppressed(self) -> None:
        text = """
#include <memory>
#include <mutex>
class Holder {
public:
    static std::shared_ptr<int> instance_;
    static std::mutex mutex_;
    static void Reset() {
        std::unique_lock<std::mutex> lock(mutex_, std::defer_lock);
        instance_.reset();
    }
};
"""
        unit = self.generated_unit("defer_lock", text)
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "blocked")
        self.assertEqual(len(run.findings), 1)
        self.assertIn("candidate/unknown", run.findings[0].message)
        self.assert_synchronization_proof_unknown(run.findings[0], "defer_lock")
        self.assertTrue(any("defer_lock does not hold" in item for item in run.limitations))

    def assert_synchronization_proof_unknown(
        self, finding, description_fragment: str = "mixed atomic/non-atomic"
    ) -> None:
        matching = [
            obligation
            for obligation in finding.evidence_obligations
            if obligation.kind == "synchronization_proof"
        ]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0].status, "unknown")
        self.assertIn(description_fragment, matching[0].description)

    def test_atomic_read_and_mutex_protected_write_is_candidate_unknown(self) -> None:
        text = """
#include <atomic>
#include <memory>
#include <mutex>
class Holder {
public:
    static std::shared_ptr<int> instance_;
    static std::mutex mutex_;
    static std::shared_ptr<int> AtomicRead() {
        return std::atomic_load(&instance_);
    }
    static void GuardedWrite() {
        std::lock_guard<std::mutex> lock(mutex_);
        instance_.reset();
    }
};
"""
        unit = self.generated_unit("atomic_read_guarded_write", text)
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(len(run.findings), 1)
        self.assertEqual(run.findings[0].evidence_type, "syntax")
        self.assertIn("instance_", unit.text.splitlines()[run.findings[0].line - 1])
        self.assert_synchronization_proof_unknown(run.findings[0])

    def test_atomic_write_and_mutex_protected_read_is_candidate_unknown(self) -> None:
        text = """
#include <atomic>
#include <memory>
#include <mutex>
class Holder {
public:
    static std::shared_ptr<int> instance_;
    static std::mutex mutex_;
    static void AtomicWrite() {
        std::atomic_store(&instance_, std::shared_ptr<int>(nullptr));
    }
    static bool GuardedRead() {
        std::lock_guard<std::mutex> lock(mutex_);
        return static_cast<bool>(instance_);
    }
};
"""
        unit = self.generated_unit("atomic_write_guarded_read", text)
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(len(run.findings), 1)
        self.assertIn("instance_", unit.text.splitlines()[run.findings[0].line - 1])
        self.assert_synchronization_proof_unknown(run.findings[0])

    def test_mixed_atomic_and_non_atomic_with_different_mutexes_is_candidate(self) -> None:
        text = """
#include <atomic>
#include <memory>
#include <mutex>
class Holder {
public:
    static std::shared_ptr<int> instance_;
    static std::mutex mutex_a_;
    static std::mutex mutex_b_;
    static void AtomicWrite() {
        std::atomic_store(&instance_, std::shared_ptr<int>(nullptr));
    }
    static void GuardedA() {
        std::lock_guard<std::mutex> lock(mutex_a_);
        instance_.reset();
    }
    static bool GuardedB() {
        std::lock_guard<std::mutex> lock(mutex_b_);
        return static_cast<bool>(instance_);
    }
};
"""
        unit = self.generated_unit("mixed_atomic_different_mutexes", text)
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(len(run.findings), 2)
        self.assertEqual({finding.line for finding in run.findings}, {
            text.splitlines().index("        instance_.reset();") + 1,
            text.splitlines().index("        return static_cast<bool>(instance_);") + 1,
        })
        for finding in run.findings:
            self.assert_synchronization_proof_unknown(finding)

    def test_explicit_atomic_api_is_atomic_and_mixed_with_ordinary_write(self) -> None:
        text = """
#include <atomic>
#include <memory>
#include <mutex>
class Holder {
public:
    static std::shared_ptr<int> instance_;
    static std::mutex mutex_;
    static std::shared_ptr<int> AtomicRead() {
        return std::atomic_load_explicit(&instance_, std::memory_order_acquire);
    }
    static void GuardedWrite() {
        std::lock_guard<std::mutex> lock(mutex_);
        instance_.reset();
    }
};
"""
        unit = self.generated_unit("explicit_atomic_mixed", text)
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(len(run.findings), 1)
        self.assertIn("instance_", unit.text.splitlines()[run.findings[0].line - 1])
        self.assert_synchronization_proof_unknown(run.findings[0])

    def test_atomic_exchange_and_compare_exchange_are_modeled_as_atomic_writes(self) -> None:
        text = """
#include <atomic>
#include <memory>
class Holder {
public:
    static std::shared_ptr<int> instance_;
    static void Exchange() {
        std::atomic_exchange(&instance_, std::shared_ptr<int>(nullptr));
    }
    static bool CompareExchange() {
        std::shared_ptr<int> expected;
        return std::atomic_compare_exchange_strong(
            &instance_, &expected, std::shared_ptr<int>(nullptr));
    }
    static bool OrdinaryRead() {
        return static_cast<bool>(instance_);
    }
};
"""
        unit = self.generated_unit("atomic_exchange_compare_exchange", text)
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(len(run.findings), 1)
        self.assertIn("instance_", unit.text.splitlines()[run.findings[0].line - 1])
        self.assert_synchronization_proof_unknown(run.findings[0])

    def test_mixed_atomic_and_ordinary_access_under_same_reliable_mutex_is_suppressed(self) -> None:
        text = """
#include <atomic>
#include <memory>
#include <mutex>
class Holder {
public:
    static std::shared_ptr<int> instance_;
    static std::mutex mutex_;
    static std::shared_ptr<int> AtomicRead() {
        std::lock_guard<std::mutex> lock(mutex_);
        return std::atomic_load(&instance_);
    }
    static void OrdinaryWrite() {
        std::lock_guard<std::mutex> lock(mutex_);
        instance_.reset();
    }
};
"""
        unit = self.generated_unit("mixed_same_reliable_mutex", text)
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(run.findings, ())
        self.assertTrue(any("all potential conflicting access pairs" in item for item in run.limitations))
    def test_mixed_atomic_and_mutex_paths_are_candidate_unknown_not_safe(self) -> None:
        text = """
#include <atomic>
#include <memory>
#include <mutex>
class Holder {
public:
    static std::shared_ptr<int> instance_;
    static std::mutex mutex_;
    static void ResetGuarded() {
        std::lock_guard<std::mutex> lock(mutex_);
        instance_.reset();
    }
    static void AtomicReset() {
        std::atomic_store(&instance_, std::shared_ptr<int>(nullptr));
    }
};
"""
        unit = self.generated_unit("mixed_atomic_mutex", text)
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(len(run.findings), 1)
        self.assertIn("candidate/unknown", run.findings[0].message)
        self.assert_synchronization_proof_unknown(run.findings[0])
        self.assertTrue(
            any("mixed atomic/non-atomic synchronization protocol" in item for item in run.limitations)
        )

    def test_constructor_initialization_and_stable_read_are_not_race_candidates(self) -> None:
        text = """
#include <memory>
class Holder {
public:
    std::shared_ptr<int> instance_;
    Holder() : instance_(nullptr) {}
    int Read() const { return instance_ ? 1 : 0; }
};
"""
        unit = self.generated_unit("constructor_stable_owner", text)
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(run.findings, ())
        self.assertTrue(
            any("constructor initialization followed only by stable reads" in item for item in run.limitations)
        )

    def test_cross_file_access_pair_is_aggregated(self) -> None:
        declaration = self.generated_unit(
            "cross_file_declaration",
            """
#include <memory>
class Holder {
public:
    std::shared_ptr<int> instance_;
    void Set(std::shared_ptr<int> value);
    int Read() const;
};
""",
        )
        definitions = self.generated_unit(
            "cross_file_definitions",
            """
#include <memory>
void Holder::Set(std::shared_ptr<int> value) { instance_ = value; }
int Holder::Read() const { return instance_ ? 1 : 0; }
""",
        )
        run = self.detector.detect(self.context, (declaration, definitions))
        self.assertEqual(run.status, "completed")
        self.assertEqual(len(run.findings), 2)
        self.assertEqual(
            {finding.file for finding in run.findings},
            {definitions.path},
        )
        for finding in run.findings:
            self.assert_synchronization_proof_unknown(
                finding, "cross-function synchronization protocol is unknown"
            )

    def test_cross_file_pair_under_same_reliable_mutex_is_narrowly_suppressed(self) -> None:
        declaration = self.generated_unit(
            "cross_file_mutex_declaration",
            """
#include <memory>
#include <mutex>
class Holder {
public:
    std::shared_ptr<int> instance_;
    std::mutex mutex_;
    void Set(std::shared_ptr<int> value);
    int Read() const;
};
""",
        )
        definitions = self.generated_unit(
            "cross_file_mutex_definitions",
            """
#include <memory>
#include <mutex>
void Holder::Set(std::shared_ptr<int> value) {
    std::lock_guard<std::mutex> guard(mutex_);
    instance_ = value;
}
int Holder::Read() const {
    std::lock_guard<std::mutex> guard(mutex_);
    return instance_ ? 1 : 0;
}
""",
        )
        run = self.detector.detect(self.context, (declaration, definitions))
        self.assertEqual(run.status, "completed")
        self.assertEqual(run.findings, ())
        self.assertTrue(
            any("all potential conflicting access pairs" in item for item in run.limitations)
        )

    def test_simple_intra_function_object_alias_binds_the_member(self) -> None:
        text = """
#include <memory>
class Holder {
public:
    std::shared_ptr<int> instance_;
    void Mutate() {
        Holder holder;
        Holder* alias = &holder;
        alias->instance_ = std::make_shared<int>(1);
        bool ready = static_cast<bool>(alias->instance_);
        (void)ready;
    }
};
"""
        unit = self.generated_unit("intra_function_object_alias", text)
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.status, "completed")
        self.assertGreaterEqual(len(run.findings), 1)
        self.assertTrue(all(item.symbol == "instance_" for item in run.findings))
        self.assertIn(
            "no reliable mutex covers the pair",
            run.findings[0].message + run.findings[-1].message,
        )


if __name__ == "__main__":
    unittest.main()
