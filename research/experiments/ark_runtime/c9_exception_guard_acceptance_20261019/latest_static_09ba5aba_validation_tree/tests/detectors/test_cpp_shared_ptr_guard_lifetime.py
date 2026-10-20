"""Guard lifetime controls; authored inputs are not a product truth set."""
from pathlib import Path
import hashlib
import unittest

from src.ohscanner.contracts import SourceUnit
from src.ohscanner.detectors.cpp.m2_adapter import M2SharedPtrRaceDetector
from src.ohscanner.detectors.cpp.shared_ptr_race_detector import SharedPtrRaceDetector
from tests.detectors.shared_ptr_race_fixture_support import (
    load_shared_ptr_race_units, shared_ptr_race_context, unit_by_path,
)


class SharedPtrGuardLifetimeTests(unittest.TestCase):
    def setUp(self):
        self.context = shared_ptr_race_context()
        self.detector = SharedPtrRaceDetector()

    def unit(self, action):
        text = """#include <memory>
#include <mutex>
class C {
 static std::shared_ptr<int> slot_;
 static std::mutex mutex_;
 static std::mutex other_;
 static void Consume(std::unique_lock<std::mutex>&);
 static std::shared_ptr<int> Value(std::unique_lock<std::mutex>&);
public:
 void Set(std::shared_ptr<int> value) {
  std::unique_lock<std::mutex> guard(mutex_);
  ACTION
 }
 std::shared_ptr<int> Get() {
  std::lock_guard<std::mutex> guard(mutex_);
  return slot_;
 }
};
""".replace("ACTION", action)
        return SourceUnit(path="guard_control.cpp", language="cpp", text=text,
                          sha256=hashlib.sha256(text.encode()).hexdigest(), parse_status="complete")

    def assert_candidate_unknown(self, action):
        unit = self.unit(action)
        run = self.detector.detect(self.context, (unit,))
        self.assertTrue(run.findings, action)
        self.assertEqual(run.status, "blocked")
        self.assertTrue(any("guard" in x and "ownership" in x for x in run.limitations))
        for finding in run.findings:
            self.assertEqual(finding.source_sha256, unit.sha256)
            self.assertEqual(finding.candidate_cwe, "CWE-362")
            self.assertEqual(finding.evidence_type, "syntax")
            self.assertTrue(any(x.kind == "synchronization_proof" and x.status == "unknown"
                                for x in finding.evidence_obligations))
        return run

    def test_four_manifest_controls(self):
        directory = Path(__file__).parent / "fixtures" / "cpp_guard_lifetime"
        units = tuple(SourceUnit(path=f.name, language="cpp", text=f.read_text(),
                                 sha256=hashlib.sha256(f.read_bytes()).hexdigest(), parse_status="complete")
                      for f in sorted(directory.glob("*.cpp")))
        positive = self.detector.detect(self.context, (unit_by_path(units, "vulnerable_guard_unlock.cpp"),))
        self.assertTrue(positive.findings)
        self.assertEqual(positive.status, "blocked")
        for name in ("fixed_guard_held.cpp", "safe_access_before_guard_unlock.cpp",
                     "unrelated_plain_pointer_guard_unlock.cpp"):
            with self.subTest(name=name):
                run = self.detector.detect(self.context, (unit_by_path(units, name),))
                self.assertEqual(run.findings, ())
                self.assertEqual(run.status, "completed")

    def test_explicit_unlock_cannot_suppress_the_write(self):
        run = self.assert_candidate_unknown("guard.unlock(); slot_ = value;")
        self.assertTrue(any("unlock" in x for x in run.limitations))

    def test_release_is_ownership_unknown_not_an_asserted_mutex_unlock(self):
        run = self.assert_candidate_unknown("auto* mutex = guard.release(); slot_ = value;")
        self.assertTrue(any("release" in x and "does not itself unlock" in x for x in run.limitations))

    def test_guard_transfer_assignment_swap_and_escape_are_unknown(self):
        for action in (
            "{ std::unique_lock<std::mutex> moved(std::move(guard)); } slot_ = value;",
            "guard = std::unique_lock<std::mutex>(other_); slot_ = value;",
            "std::unique_lock<std::mutex> second(other_); guard.swap(second); slot_ = value;",
            "Consume(guard); slot_ = value;",
            "auto* escaped = &guard; slot_ = value;",
        ):
            with self.subTest(action=action):
                self.assert_candidate_unknown(action)

    def test_relocking_does_not_reestablish_a_cfg_proof(self):
        self.assert_candidate_unknown("guard.unlock(); guard.lock(); slot_ = value;")

    def test_guard_escape_in_write_rhs_invalidates_the_entire_statement(self):
        self.assert_candidate_unknown("slot_ = Value(guard);")

    def test_owned_lock_query_and_later_unlock_do_not_invalidate_earlier_access(self):
        for action in ("slot_ = value; guard.unlock();", "if (guard.owns_lock()) { slot_ = value; }"):
            with self.subTest(action=action):
                run = self.detector.detect(self.context, (self.unit(action),))
                self.assertEqual(run.findings, ())
                self.assertEqual(run.status, "completed")

    def test_nested_guard_with_same_name_does_not_invalidate_outer_guard(self):
        unit = self.unit("{ std::unique_lock<std::mutex> guard(other_); guard.unlock(); } slot_ = value;")
        run = self.detector.detect(self.context, (unit,))
        self.assertEqual(run.findings, ())
        self.assertEqual(run.status, "completed")

    def test_comments_literals_and_unrelated_object_member_are_ignored(self):
        action = ('// guard.unlock();\n  const char* note = "guard.unlock()"; '
                  'other.guard.unlock(); slot_ = value;')
        run = self.detector.detect(self.context, (self.unit(action),))
        self.assertEqual(run.findings, ())

    def test_public_adapter_preserves_candidate_and_partial_file_outcome(self):
        unit = self.unit("guard.unlock(); slot_ = value;")
        run = M2SharedPtrRaceDetector().detect(self.context, (unit,))
        self.assertTrue(run.findings)
        self.assertEqual(run.status, "blocked")
        self.assertEqual(run.file_outcomes, ((unit.path, "partial"),))
        self.assertTrue(all(x.source_sha256 == unit.sha256 for x in run.findings))
        self.assertTrue(all(any(o.kind == "thread_interleaving" and o.status == "unknown"
                                for o in x.evidence_obligations) for x in run.findings))
