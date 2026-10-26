from __future__ import annotations

import unittest

from tests.detectors.null_dereference_fixture_support import (
    EXPECTED_FIXTURE_COUNT,
    EXPECTED_MANIFEST_SHA256,
    EXPECTED_MATRIX_SHA256,
    EXPECTED_SNAPSHOT_SHA256,
    load_null_fixture_package,
)


def make_detector():
    from src.ohscanner.detectors.cpp.null_dereference_detector import (
        NullDereferenceDetector,
    )

    return NullDereferenceDetector()


def expected_status(coverage: str) -> str:
    if coverage == "failed":
        return "failed"
    if coverage in ("partial", "not_analyzed"):
        return "blocked"
    return "completed"


class NullDereferenceFixtureIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.package = load_null_fixture_package()

    def test_package_is_exactly_the_preexisting_18_fixture_matrix(self) -> None:
        self.assertEqual(len(self.package.units), EXPECTED_FIXTURE_COUNT)
        self.assertEqual(len(self.package.cases_by_fixture), EXPECTED_FIXTURE_COUNT)
        self.assertEqual(
            self.package.manifest["provenance"]["snapshot_sha256"],
            EXPECTED_SNAPSHOT_SHA256,
        )
        self.assertEqual(
            self.package.manifest["provenance"]["regression_matrix_sha256"],
            EXPECTED_MATRIX_SHA256,
        )
        self.assertEqual(
            {unit.path.rsplit("/", 1)[-1] for unit in self.package.units},
            set(self.package.cases_by_fixture),
        )
        for unit in self.package.units:
            self.assertEqual(len(unit.sha256), 64)

    def test_manifest_and_matrix_identity_constants_are_stable(self) -> None:
        import hashlib
        from tests.detectors.null_dereference_fixture_support import (
            MANIFEST_PATH,
            MATRIX_PATH,
        )

        self.assertEqual(
            hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest(),
            EXPECTED_MANIFEST_SHA256,
        )
        self.assertEqual(
            hashlib.sha256(MATRIX_PATH.read_bytes()).hexdigest(),
            EXPECTED_MATRIX_SHA256,
        )

    def test_owner_approval_record_binds_approver_date_and_commit(self) -> None:
        import json
        from tests.detectors.null_dereference_fixture_support import ROOT

        approval_path = ROOT / "research" / "contracts" / "a_ccr_04" / "owner_approval.json"
        approval = json.loads(approval_path.read_text(encoding="utf-8"))
        self.assertEqual(approval["status"], "approved")
        self.assertEqual(approval["approver"], "lh")
        self.assertEqual(approval["approval_date"], "2026-10-15")
        self.assertRegex(approval["approved_commit"], r"^[0-9a-f]{40}$")
        self.assertEqual(approval["approved_change_request"], "A-CCR-04")
        self.assertTrue(approval["authorization"]["detector_implementation"])


class NullDereferenceFixtureRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.package = load_null_fixture_package()
        cls.detector = make_detector()

    def test_declares_exact_identity_and_scope(self) -> None:
        self.assertEqual(self.detector.detector_id, "ohscanner.cpp.null_dereference")
        self.assertEqual(self.detector.version, "0.2.0")
        self.assertEqual(self.detector.supported_languages, ("c", "cpp"))
        self.assertEqual(self.detector.required_facts, ())
        self.assertEqual(self.detector.ast_scope, "per_file")
        self.assertEqual(self.package.context.shared_facts, {})

    def test_all_18_fixture_observations_match_matrix(self) -> None:
        expected_obligations = [
            (item["kind"], item["candidate_status"])
            for item in self.package.matrix["evidence_obligations"]
        ]
        for unit in self.package.units:
            fixture = unit.path.rsplit("/", 1)[-1]
            with self.subTest(fixture=fixture):
                case = self.package.cases_by_fixture[fixture]
                run = self.detector.detect(self.package.context, (unit,))
                self.assertEqual(run.detector_id, self.detector.detector_id)
                self.assertEqual(run.version, self.detector.version)
                self.assertEqual(
                    dict(run.file_outcomes),
                    {unit.path: case["expected_coverage"]},
                )
                self.assertEqual(run.status, expected_status(case["expected_coverage"]))

                expected_count = case["expected_finding_count"]
                if expected_count is None:
                    self.assertEqual(run.findings, ())
                else:
                    self.assertEqual(len(run.findings), expected_count)

                for finding in run.findings:
                    self.assertEqual(finding.file, unit.path)
                    self.assertEqual(finding.rule_id, "ohcpp-null-dereference-candidate-001")
                    self.assertEqual(finding.evidence_type, "syntax")
                    self.assertEqual(finding.candidate_cwe, "CWE-476")
                    self.assertEqual(finding.source_sha256, unit.sha256)
                    self.assertIsNone(finding.consequence_impact)
                    self.assertIsNone(finding.consequence_cwe)
                    self.assertEqual(
                        [(item.kind, item.status) for item in finding.evidence_obligations],
                        expected_obligations,
                    )
                    self.assertIn("null_source=" + case["null_source"], finding.message)
                    self.assertIn("sink=" + case["sink"], finding.message)
                    self.assertIn("guard_relation=" + case["guard_relation"], finding.message)
                    if case["error_path"] != "unknown":
                        self.assertIn("error_path=" + case["error_path"], finding.message)
                    self.assertIn("candidate/unassessed", finding.message)

                if not run.findings and case["expected_coverage"] == "complete":
                    self.assertTrue(
                        any("narrow negative only" in item for item in run.limitations),
                        run.limitations,
                    )
                    self.assertTrue(
                        any("not a safe verdict" in item for item in run.limitations),
                        run.limitations,
                    )
                for reason in case.get("unknown_reasons", ()):
                    if expected_count:
                        self.assertTrue(
                            any(reason in item for item in run.limitations),
                            (reason, run.limitations),
                        )
                if case["expected_coverage"] in ("failed", "not_analyzed"):
                    self.assertTrue(
                        any("No absence, safety, miss" in item for item in run.limitations),
                        run.limitations,
                    )

    def test_combined_18_unit_run_retains_candidates_and_fails_closed(self) -> None:
        run = self.detector.detect(self.package.context, self.package.units)
        outcomes = dict(run.file_outcomes)
        self.assertEqual(set(outcomes), {unit.path for unit in self.package.units})
        self.assertEqual(run.status, "failed")
        self.assertEqual(
            {
                value: sum(item == value for item in outcomes.values())
                for value in ("complete", "partial", "failed", "not_analyzed")
            },
            {
                "complete": 10,
                "partial": 6,
                "failed": 1,
                "not_analyzed": 1,
            },
        )
        self.assertEqual(len(run.findings), 11)
        self.assertTrue(all(f.source_sha256 for f in run.findings))
        self.assertTrue(
            any("No absence, safety, miss" in item for item in run.limitations)
        )
        self.assertTrue(
            any("zero findings" in item.lower() for item in run.limitations)
        )

    def test_failed_and_not_analyzed_publish_no_safety_or_miss_claim(self) -> None:
        for fixture, coverage in (
            ("unknown_failed_parse.cpp", "failed"),
            ("not_analyzed_no_cpp_shape.js", "not_analyzed"),
        ):
            with self.subTest(fixture=fixture):
                unit = next(
                    item
                    for item in self.package.units
                    if item.path.rsplit("/", 1)[-1] == fixture
                )
                run = self.detector.detect(self.package.context, (unit,))
                self.assertEqual(dict(run.file_outcomes), {unit.path: coverage})
                self.assertEqual(run.findings, ())
                joined = "\n".join(run.limitations).lower()
                self.assertIn("no absence, safety, miss", joined)
                self.assertNotIn("is safe", joined)
                self.assertNotIn("no vulnerability", joined)
                self.assertNotIn("expected miss", joined)

    def test_same_line_identical_sinks_keep_one_runner_identity(self) -> None:
        import hashlib

        from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
        from src.ohscanner.fixture import snapshot_digest
        from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage

        text = "int f(int *p) { return *p + *p; }\n"
        unit = SourceUnit(
            "duplicate.cpp",
            "cpp",
            text,
            hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "complete",
        )
        context = ScanContext(
            ScanRequest(
                "null-duplicate-identity",
                "fixture/null-duplicate",
                "synthetic-null-v1",
                snapshot_digest((unit,)),
                "current-component:fixture/null-duplicate",
            ),
            (unit,),
            {},
        )
        registry = DetectorRegistry()
        registry.register(make_detector())
        reports, _sidecar = run_all_with_coverage(context, registry)
        self.assertEqual(reports[0].status, "completed")
        self.assertEqual(reports[0].diagnostic_count, 1)
        self.assertEqual(len(reports[0].diagnostics), 1)

    def test_output_is_deterministic_across_replays(self) -> None:
        first = self.detector.detect(self.package.context, self.package.units)
        second = self.detector.detect(self.package.context, self.package.units)
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
