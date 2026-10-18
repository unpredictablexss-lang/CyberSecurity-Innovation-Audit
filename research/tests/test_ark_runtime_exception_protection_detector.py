from __future__ import annotations
import hashlib
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
EXACT = ROOT / "research/experiments/ark-runtime-exact-source-20261018/sources"
sys.path.insert(0, str(ROOT))

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from research.full_scan_20261018.lanes.c.exception_protection import (
    ArkRuntimeExceptionProtectionDetector, TARGET_PATH, RULE_ID, analyze_unit,
)
from research.full_scan_20261018.lanes.c.syntax import parse_functions

REPO = "openharmony/arkcompiler_ets_runtime"
PARENT_COMMIT = "2e2cebedf5a96fb798144c82296b8b55e2eb60c6"
FIX_COMMIT = "c80d853d1b3be23ca999618a199183bc854eaa6a"


def make_unit(name: str, commit: str) -> SourceUnit:
    data = (EXACT / name).read_bytes()
    return SourceUnit(TARGET_PATH, "cpp", data.decode("utf-8"), hashlib.sha256(data).hexdigest(), "partial")


def context(unit: SourceUnit, commit: str) -> ScanContext:
    return ScanContext(
        request=ScanRequest(
            request_id="research:ark-runtime-exception:" + commit[:12],
            repository=REPO,
            commit=commit,
            snapshot_sha256=unit.sha256,
            target_id="current-component:" + REPO,
            profile_id="light-ast",
            provenance="git_object",
        ),
        units=(unit,),
        shared_facts={"ast": {unit.path: object()}},
    )


class ExceptionPropagationDetectorTests(unittest.TestCase):
    def test_exact_parent_is_candidate_with_source_bound_obligations(self):
        unit = make_unit("exception-parent.cpp", PARENT_COMMIT)
        result = analyze_unit(unit)
        self.assertEqual([item.kind for item in result.observations], ["candidate"])
        self.assertEqual(result.observations[0].reason, "callstub_result_replaced_without_pending_exception_propagation")
        detector_run = ArkRuntimeExceptionProtectionDetector().detect(context(unit, PARENT_COMMIT), (unit,))
        self.assertEqual(detector_run.status, "blocked")
        self.assertEqual(detector_run.file_outcomes, ((TARGET_PATH, "partial"),))
        self.assertEqual(len(detector_run.findings), 1)
        finding = detector_run.findings[0]
        self.assertEqual(finding.rule_id, RULE_ID)
        self.assertEqual(finding.source_sha256, unit.sha256)
        self.assertEqual(len(finding.evidence_obligations), 5)

    def test_exact_fix_uses_pending_exception_helper(self):
        unit = make_unit("exception-fix.cpp", FIX_COMMIT)
        result = analyze_unit(unit)
        self.assertEqual([item.kind for item in result.observations], ["matched"])
        detector_run = ArkRuntimeExceptionProtectionDetector().detect(context(unit, FIX_COMMIT), (unit,))
        self.assertEqual(detector_run.status, "blocked")
        self.assertEqual(detector_run.file_outcomes, ((TARGET_PATH, "partial"),))
        self.assertEqual(detector_run.findings, ())
        self.assertIn("not registered in the product catalog", " ".join(detector_run.limitations))

    def test_unrelated_lower_call_runtime_is_not_applicable(self):
        fixed = (EXACT / "exception-fix.cpp").read_bytes()
        _, functions = parse_functions(fixed)
        fn = next(f for f in functions if f.qualified_name.endswith("SlowPathLowering::LowerCallRuntime"))
        snippet = fn.text(fn.node)
        derived_text = "namespace panda::ecmascript::kungfu {\n" + snippet + "\n}"
        digest = hashlib.sha256(derived_text.encode("utf-8")).hexdigest()
        unit = SourceUnit(TARGET_PATH, "cpp", derived_text, digest, "complete")
        result = analyze_unit(unit)
        self.assertEqual(result.file_outcome, "not_analyzed")
        self.assertIn("not_applicable_to_rule", result.limitations)

    def test_detector_rejects_mixed_source_binding(self):
        unit = make_unit("exception-parent.cpp", PARENT_COMMIT)
        other = SourceUnit(TARGET_PATH, "cpp", unit.text + "\n", hashlib.sha256((unit.text + "\n").encode()).hexdigest(), "partial")
        with self.assertRaisesRegex(ValueError, "detector_input_outside_bound_context"):
            ArkRuntimeExceptionProtectionDetector().detect(context(unit, PARENT_COMMIT), (other,))


if __name__ == "__main__":
    unittest.main()
