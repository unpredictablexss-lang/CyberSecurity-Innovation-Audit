from __future__ import annotations

import unittest

from src.ohscanner.contracts import DetectorFinding, DetectorRun
from src.ohscanner.detectors.cpp.lifetime_detector import (
    LifetimeAnalysisOptions,
    LifetimeOwnershipGuardDetector,
)
from src.ohscanner.runner import DetectorRegistry, run_all
from tests.detectors.fixture_support import lifetime_context, load_lifetime_units


class _MarkerDetector:
    detector_id = "ohscanner.test.marker"
    version = "0.0.1"
    supported_languages = ("cpp",)
    required_facts = ()

    def detect(self, context, units):
        del context
        return DetectorRun(
            detector_id=self.detector_id,
            version=self.version,
            status="completed",
            analyzed_files=tuple(sorted(unit.path for unit in units)),
        )


class _CrashingDetector:
    detector_id = "ohscanner.test.crash"
    version = "0.0.1"
    supported_languages = ("cpp",)
    required_facts = ()

    def detect(self, context, units):
        del context, units
        raise RuntimeError("synthetic detector crash")


class _DuplicateFindingDetector:
    detector_id = "ohscanner.test.duplicate"
    version = "0.0.1"
    supported_languages = ("cpp",)
    required_facts = ()

    def detect(self, context, units):
        del context
        path = units[0].path
        finding = DetectorFinding(
            file=path,
            line=1,
            rule_id="test-duplicate",
            message="synthetic duplicate identity",
        )
        return DetectorRun(
            detector_id=self.detector_id,
            version=self.version,
            status="completed",
            analyzed_files=tuple(sorted(unit.path for unit in units)),
            findings=(finding, finding),
        )


class RunnerIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.context = lifetime_context()
        self.units = load_lifetime_units()

    def test_maps_current_detector_run_to_toolrun_v1(self) -> None:
        registry = DetectorRegistry()
        registry.register(LifetimeOwnershipGuardDetector())
        result = run_all(self.context, registry)[0]
        self.assertEqual(result.schema_version, 1)
        self.assertEqual(
            result.run_id,
            self.context.request.request_id + ":ohscanner.cpp.lifetime",
        )
        self.assertEqual(result.tool, "ohscanner.cpp.lifetime")
        self.assertEqual(result.tool_version, "0.2.0-proposed")
        self.assertEqual(result.status, "blocked")
        # M2 records files that completed or were partly inspected even when
        # whole-scope coverage is blocked by other partial/failed units.
        self.assertEqual(result.scope_files, 8)
        self.assertEqual(result.diagnostic_count, 3)
        self.assertTrue(all(item.evidence_type == "syntax" for item in result.diagnostics))
        self.assertTrue(all(item.severity == "unassessed" for item in result.diagnostics))
        self.assertTrue(all(item.confidence == "unassessed" for item in result.diagnostics))
        self.assertEqual(
            [(item["file"], item["status"]) for item in result.parsing],
            [
                (unit.path, unit.parse_status)
                for unit in self.units
                if unit.language == "cpp"
            ],
        )
        payload = result.to_dict()
        self.assertEqual(payload["schema_version"], 1)
        self.assertIn("interpretation", payload)
        self.assertNotIn("validation_status", payload["diagnostics"][0])

    def test_crash_is_isolated_to_its_own_failed_record(self) -> None:
        registry = DetectorRegistry()
        registry.register(_CrashingDetector())
        registry.register(_MarkerDetector())
        results = run_all(self.context, registry)
        self.assertEqual(
            [item.tool for item in results],
            ["ohscanner.test.crash", "ohscanner.test.marker"],
        )
        self.assertEqual(results[0].status, "failed")
        self.assertTrue(
            any("Detector failed: RuntimeError" in item for item in results[0].limitations)
        )
        self.assertEqual(results[1].status, "completed")
        self.assertEqual(results[1].diagnostic_count, 0)

    def test_cooperative_timeout_is_isolated_and_later_detector_runs(self) -> None:
        registry = DetectorRegistry()
        registry.register(
            LifetimeOwnershipGuardDetector(
                LifetimeAnalysisOptions(timeout_check=lambda: True)
            )
        )
        registry.register(_MarkerDetector())
        results = run_all(self.context, registry)
        self.assertEqual(results[0].tool, "ohscanner.cpp.lifetime")
        self.assertEqual(results[0].status, "failed")
        self.assertTrue(
            any("Cooperative timeout" in item for item in results[0].limitations)
        )
        self.assertEqual(results[1].tool, "ohscanner.test.marker")
        self.assertEqual(results[1].status, "completed")

    def test_duplicate_finding_identity_fails_only_that_detector(self) -> None:
        registry = DetectorRegistry()
        registry.register(_DuplicateFindingDetector())
        registry.register(_MarkerDetector())
        results = run_all(self.context, registry)
        self.assertEqual(results[0].status, "failed")
        self.assertTrue(
            any("Detector failed: ValueError" in item for item in results[0].limitations)
        )
        self.assertEqual(results[1].status, "completed")

    def test_registry_order_and_result_order_are_stable(self) -> None:
        first = DetectorRegistry()
        first.register(_MarkerDetector())
        first.register(LifetimeOwnershipGuardDetector())
        second = DetectorRegistry()
        second.register(LifetimeOwnershipGuardDetector())
        second.register(_MarkerDetector())
        self.assertEqual(
            [item.tool for item in run_all(self.context, first)],
            [item.tool for item in run_all(self.context, second)],
        )


if __name__ == "__main__":
    unittest.main()
