from __future__ import annotations

import hashlib
from pathlib import Path
import unittest

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.detectors.cpp.algorithmic_complexity_detector import (
    CppAlgorithmicComplexityDetector, RULE_RECURSIVE_GROWTH, RULE_RECURSIVE_LOOKUP,
)
from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage

FIXTURES = Path(__file__).parent / "fixtures" / "cpp_algorithmic_complexity"


def scan(text: str, status: str = "complete"):
    unit = SourceUnit("generic.c", "c", text, hashlib.sha256(text.encode()).hexdigest(), parse_status=status)
    context = ScanContext(
        ScanRequest("test:d3", "fixture/complexity", "3" * 40, snapshot_digest((unit,)),
                    "current-component:fixture/complexity", "fixture-no-build", "fixture"),
        (unit,),
    )
    return CppAlgorithmicComplexityDetector().detect(context, (unit,))


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class AlgorithmicComplexityMechanismTests(unittest.TestCase):
    def test_recursive_compare_and_repeated_linear_lookup_candidate(self):
        run = scan(fixture("recursive_lookup_positive.c"))
        self.assertEqual(run.status, "completed")
        self.assertEqual(sum(f.rule_id == RULE_RECURSIVE_LOOKUP for f in run.findings), 1)

    def test_recursive_copy_expansion_and_cleanup_candidate(self):
        run = scan(fixture("recursive_growth_positive.c"))
        self.assertEqual(run.status, "completed")
        self.assertEqual(sum(f.rule_id == RULE_RECURSIVE_GROWTH for f in run.findings), 1)

    def test_indexed_comparison_and_bounded_simple_recursion_are_quiet(self):
        self.assertFalse(scan(fixture("fixed_safe.c")).findings)

    def test_bounded_recursive_copy_and_iterative_teardown_are_quiet(self):
        self.assertFalse(scan(fixture("recursive_growth_bounded.c")).findings)

    def test_unrelated_recursion_and_nested_loops_are_quiet(self):
        self.assertFalse(scan(fixture("unrelated.c")).findings)

    def test_partial_candidate_retained_with_unknown_run_status(self):
        run = scan(fixture("recursive_lookup_positive.c"), "partial")
        self.assertEqual(run.status, "blocked")
        self.assertTrue(any(f.rule_id == RULE_RECURSIVE_LOOKUP for f in run.findings))

    def test_runner_preserves_partial_candidate_and_unknown_coverage(self):
        source = fixture("recursive_lookup_positive.c")
        unit = SourceUnit("generic.c", "c", source, hashlib.sha256(source.encode()).hexdigest(), parse_status="partial")
        context = ScanContext(
            ScanRequest("test:d3-runner", "fixture/complexity", "3" * 40, snapshot_digest((unit,)),
                        "current-component:fixture/complexity", "fixture-no-build", "fixture"),
            (unit,),
        )
        registry = DetectorRegistry()
        registry.register(CppAlgorithmicComplexityDetector())
        reports, sidecar = run_all_with_coverage(context, registry)
        report = reports[0]
        coverage = sidecar["detectors"][CppAlgorithmicComplexityDetector.detector_id]
        self.assertEqual(report.status, "blocked")
        self.assertTrue(any(item.rule_id == RULE_RECURSIVE_LOOKUP for item in report.diagnostics))
        self.assertEqual(coverage["partially_inspected_files"], ["generic.c"])
        self.assertEqual(coverage["analyzed_files"], [])

    def test_partial_without_candidate_is_not_a_safe_verdict(self):
        run = scan(fixture("unrelated.c"), "partial")
        self.assertEqual(run.status, "blocked")
        self.assertFalse(run.findings)


if __name__ == "__main__":
    unittest.main()
