from __future__ import annotations

import dataclasses
import time
import unittest

from src.ohscanner.detectors.cpp.lifetime_detector import LifetimeOwnershipGuardDetector
from src.ohscanner.detectors.cpp.proposed_runner import (
    DetectorJob,
    run_detector_jobs,
)
from src.ohscanner.detectors.cpp.proposed_toolrun_bridge import (
    map_detector_run_to_toolrun_v1,
)
from tests.detectors.fixture_support import (
    lifetime_context,
    load_lifetime_units,
    unit_by_path,
)


class ProposedBridgeAndIsolationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.context = lifetime_context()
        self.units = load_lifetime_units()
        self.vulnerable = unit_by_path(self.units, "vulnerable_unserialized.cpp")

    def test_maps_local_run_to_existing_toolrun_v1_without_new_schema(self) -> None:
        run = LifetimeOwnershipGuardDetector().detect(self.context, (self.vulnerable,))
        result = map_detector_run_to_toolrun_v1(self.context.request, run, "fixture-run:001")
        self.assertEqual(result.schema_version, 1)
        self.assertEqual(result.tool, "ohscanner.cpp.lifetime")
        self.assertEqual(result.tool_version, "0.1.0-proposed")
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.scope_files, 1)
        self.assertEqual(result.diagnostic_count, 1)
        self.assertEqual(result.diagnostics[0].evidence_type, "syntax")
        self.assertEqual(result.diagnostics[0].severity, "unassessed")
        self.assertEqual(result.parsing, [{"file": self.vulnerable.path, "status": "complete"}])
        payload = result.to_dict()
        self.assertIn("interpretation", payload)
        self.assertNotIn("validation_status", payload["diagnostics"][0])

    def test_bridge_deduplicates_diagnostic_ids_deterministically(self) -> None:
        detector_run = LifetimeOwnershipGuardDetector().detect(self.context, (self.vulnerable,))
        candidate = detector_run.diagnostics[0]
        duplicated = dataclasses.replace(detector_run, diagnostics=(candidate, candidate))
        result = map_detector_run_to_toolrun_v1(self.context.request, duplicated, "fixture-run:002")
        self.assertEqual(result.diagnostic_count, 1)
        self.assertTrue(any("Duplicate diagnostic_id" in item for item in result.limitations))

    def test_crash_isolated_to_its_own_failed_record(self) -> None:
        def crash() -> object:
            raise RuntimeError("synthetic detector crash")

        success = LifetimeOwnershipGuardDetector().detect(self.context, (self.vulnerable,))
        results = run_detector_jobs(
            (
                DetectorJob("aaa.test-crash", "0.0.1", crash),
                DetectorJob(success.detector_id, success.version, lambda: success),
            ),
            timeout_seconds=0.5,
        )
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].detector_id, "aaa.test-crash")
        self.assertEqual(results[0].status, "failed")
        self.assertEqual(results[0].failure_kind, "exception")
        self.assertEqual(results[1].status, "completed")
        self.assertEqual(len(results[1].diagnostics), 1)

    def test_timeout_isolated_and_later_detector_still_runs(self) -> None:
        def slow() -> object:
            time.sleep(0.2)
            return None

        success = LifetimeOwnershipGuardDetector().detect(self.context, (self.vulnerable,))
        results = run_detector_jobs(
            (
                DetectorJob("aaa.test-timeout", "0.0.1", slow),
                DetectorJob(success.detector_id, success.version, lambda: success),
            ),
            timeout_seconds=0.01,
        )
        self.assertEqual(results[0].status, "failed")
        self.assertEqual(results[0].failure_kind, "timeout")
        self.assertEqual(results[1].status, "completed")
        self.assertEqual(len(results[1].diagnostics), 1)

    def test_runner_rejects_non_positive_timeout(self) -> None:
        with self.assertRaises(ValueError):
            run_detector_jobs((), timeout_seconds=0)


if __name__ == "__main__":
    unittest.main()
