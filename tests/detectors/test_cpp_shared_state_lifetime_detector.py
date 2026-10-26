from __future__ import annotations

import hashlib
from pathlib import Path
import unittest

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage
from src.ohscanner.detectors.cpp.shared_state_lifetime_detector import (
    CppSharedStateLifetimeDetector, RULE_STALE_SHARED_INPUT,
)

FIXTURES = Path(__file__).parent / "fixtures" / "cpp_shared_state_lifetime"


def scan(text: str, status="complete"):
    unit = SourceUnit("codec.c", "c", text, hashlib.sha256(text.encode()).hexdigest(), parse_status=status)
    return scan_units((unit,))


def scan_units(units):
    units = tuple(sorted(units, key=lambda unit: unit.path))
    context = ScanContext(
        ScanRequest("test:d3-shared-state", "fixture/decompressor", "4" * 40,
                    snapshot_digest(units), "current-component:fixture/decompressor",
                    "fixture-no-build", "fixture"), units,
    )
    return CppSharedStateLifetimeDetector().detect(context, units)


def fixture(name):
    return (FIXTURES / name).read_text(encoding="utf-8")


class SharedStateLifetimeDetectorTests(unittest.TestCase):
    def test_unrelated_decompressor_sibling_positive(self):
        run = scan(fixture("decompressor_sibling_positive.c"))
        self.assertEqual(run.status, "completed")
        self.assertEqual(sum(f.rule_id == RULE_STALE_SHARED_INPUT for f in run.findings), 1)

    def test_header_declared_pointer_typedef_is_resolved(self):
        text = fixture("decompressor_sibling_positive.c").replace(
            "struct RasterContext *state", "RasterRef state"
        )
        header_text = fixture("pointer_aliases.h")
        header = SourceUnit("pointer_aliases.h", "cpp", header_text,
                            hashlib.sha256(header_text.encode()).hexdigest())
        source = SourceUnit("codec.c", "c", text, hashlib.sha256(text.encode()).hexdigest())
        run = scan_units((header, source))
        self.assertTrue(any(f.rule_id == RULE_STALE_SHARED_INPUT for f in run.findings))

    def test_fixed_clear_state_helper_suppresses_candidate(self):
        self.assertFalse(scan(fixture("fixed_clear_state.c")).findings)

    def test_safe_consumer_without_release_transition_is_quiet(self):
        self.assertFalse(scan(fixture("safe_unrelated.c")).findings)

    def test_partial_positive_retained_but_run_blocked(self):
        run = scan(fixture("decompressor_sibling_positive.c"), "partial")
        self.assertEqual(run.status, "blocked")
        self.assertTrue(any(f.rule_id == RULE_STALE_SHARED_INPUT for f in run.findings))

    def test_partial_empty_remains_unknown(self):
        run = scan(fixture("safe_unrelated.c"), "partial")
        self.assertEqual(run.status, "blocked")
        self.assertFalse(run.findings)

    def test_runner_normalization_preserves_candidate_and_blocked_coverage(self):
        text = fixture("decompressor_sibling_positive.c")
        unit = SourceUnit("codec.c", "c", text, hashlib.sha256(text.encode()).hexdigest(), parse_status="partial")
        context = ScanContext(
            ScanRequest("test:d3-runner", "fixture/decompressor", "5" * 40,
                        snapshot_digest((unit,)), "current-component:fixture/decompressor",
                        "fixture-no-build", "fixture"), (unit,),
        )
        registry = DetectorRegistry()
        registry.register(CppSharedStateLifetimeDetector())
        results, sidecar = run_all_with_coverage(context, registry)
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].diagnostics)
        self.assertEqual(sidecar["detectors"][CppSharedStateLifetimeDetector.detector_id]["status"], "partial")


if __name__ == "__main__":
    unittest.main()
