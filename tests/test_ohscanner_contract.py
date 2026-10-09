"""M0 first-party detector interface, source provenance and failure tests."""

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from src.ohscanner.contracts import (
    DetectorFinding, DetectorRun, ScanContext, ScanRequest, SourceUnit,
    safe_relative_path,
)
from src.ohscanner.fixture import load_fixture, snapshot_digest, verify_fixture_unchanged
from src.ohscanner.mocks import MockCppDetector, MockInterfaceDetector
from src.ohscanner.runner import DetectorRegistry, run_all
from src.ohscanner.smoke import run_mock_smoke

FIXTURE = Path(__file__).parent / "fixtures" / "ohscanner"


def context_for(units):
    return ScanContext(
        ScanRequest("t-1", "fixture/ohscanner-core", "synthetic", snapshot_digest(units),
                    "current-component:fixture/ohscanner-core"),
        tuple(units)
    )


class DetectorContractTests(unittest.TestCase):
    def test_two_mock_detectors_normalize_to_existing_v1_schema(self):
        context = load_fixture(FIXTURE)
        registry = DetectorRegistry()
        registry.register(MockCppDetector())
        registry.register(MockInterfaceDetector())
        reports = run_all(context, registry)
        self.assertEqual(len(reports), 2)
        self.assertEqual([r.status for r in reports], ["completed", "completed"])
        self.assertEqual([r.diagnostic_count for r in reports], [1, 1])
        for report in reports:
            data = report.to_dict()
            self.assertEqual(data["schema_version"], 1)
            self.assertEqual(data["target_id"], context.request.target_id)
            self.assertEqual(data["commit"], context.request.commit)
            self.assertEqual(data["diagnostics"][0]["confidence"], "unassessed")
            self.assertEqual(data["diagnostics"][0]["severity"], "unassessed")
            self.assertEqual(data["parsing"][0]["status"], "not_run")
            self.assertEqual(report.scope_files, 1)

    def test_report_and_snapshot_digest_are_reproducible(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = run_mock_smoke(FIXTURE, root / "report.json", root / "report.md")
            self.assertEqual(report["validated_vulnerability"], 0)
            self.assertEqual(report["experiment_kind"], "m0_synthetic_contract_smoke")
            self.assertTrue((root / "report.md").exists())
            self.assertEqual(report["snapshot_sha256"], load_fixture(FIXTURE).request.snapshot_sha256)

    def test_same_report_destination_is_rejected(self):
        with self.assertRaises(ValueError):
            run_mock_smoke(FIXTURE, Path("/tmp/out"), Path("/tmp/out"))

    def test_reject_unsafe_paths(self):
        for path in ("../escape.cpp", "/root/other.cpp", "dir/../escape.cpp",
                     "dir//other.cpp", "a\\b.cpp", "C:/outside.cpp", "./a.cpp"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                safe_relative_path(path)

    def test_content_hash_is_binding(self):
        with self.assertRaises(ValueError):
            SourceUnit("sample.cpp", "cpp", "real content", "a" * 64)

    def test_duplicate_units_are_rejected(self):
        data = "x"
        unit = SourceUnit("a.cpp", "cpp", data, hashlib.sha256(data.encode()).hexdigest())
        with self.assertRaises(ValueError):
            context_for((unit, unit))

    def test_request_target_must_match_repository(self):
        with self.assertRaises(ValueError):
            ScanRequest("a", "fixture/a", "synthetic", "0" * 64, "current-component:fixture/b")

    def test_unsupported_language_is_explicitly_blocked(self):
        units = (SourceUnit("example.js", "js", "hello", hashlib.sha256(b"hello").hexdigest()),)
        reg = DetectorRegistry()
        reg.register(MockCppDetector())
        report = run_all(context_for(units), reg)[0]
        self.assertEqual(report.status, "blocked")
        self.assertEqual(report.scope_files, 0)
        self.assertEqual(report.diagnostic_count, 0)
        self.assertTrue(any("not_applicable" in item for item in report.limitations))

    def test_missing_shared_facts_is_blocked(self):
        class NeedsAst(MockCppDetector):
            required_facts = ("ast",)
        reg = DetectorRegistry()
        reg.register(NeedsAst())
        report = run_all(load_fixture(FIXTURE), reg)[0]
        self.assertEqual(report.status, "blocked")
        self.assertTrue(any("Missing required" in x for x in report.limitations))

    def test_duplicate_detector_registration_rejected(self):
        reg = DetectorRegistry()
        reg.register(MockCppDetector())
        with self.assertRaises(ValueError):
            reg.register(MockCppDetector())

    def test_bad_plugin_cannot_take_down_other_plugin(self):
        class Broken(MockCppDetector):
            detector_id = "ohscanner.mock.broken"
            def detect(self, context, units):
                raise RuntimeError("synthetic failure")

        reg = DetectorRegistry()
        reg.register(Broken())
        reg.register(MockInterfaceDetector())
        results = run_all(load_fixture(FIXTURE), reg)
        self.assertEqual([r.status for r in results], ["failed", "completed"])
        self.assertEqual(results[1].diagnostic_count, 1)
        self.assertFalse(any("synthetic failure" in x for x in results[0].limitations))

    def test_out_of_scope_candidate_is_not_normalized_as_success(self):
        class WrongPath(MockCppDetector):
            def detect(self, context, units):
                return DetectorRun(self.detector_id, self.version, "completed",
                    analyzed_files=tuple(u.path for u in units),
                    findings=(DetectorFinding("../escape.cpp", 1, "bad", "bad"),))

        reg = DetectorRegistry()
        reg.register(WrongPath())
        self.assertEqual(run_all(load_fixture(FIXTURE), reg)[0].status, "failed")

    def test_out_of_range_line_is_failed(self):
        class BadLine(MockCppDetector):
            def detect(self, context, units):
                return DetectorRun(self.detector_id, self.version, "completed",
                    analyzed_files=tuple(u.path for u in units),
                    findings=(DetectorFinding(units[0].path, 9999, "bad", "bad"),))
        reg = DetectorRegistry()
        reg.register(BadLine())
        self.assertEqual(run_all(load_fixture(FIXTURE), reg)[0].status, "failed")

    def test_partial_scope_cannot_claim_completed(self):
        class Omitted(MockCppDetector):
            def detect(self, context, units):
                return DetectorRun(self.detector_id, self.version, "completed")
        reg = DetectorRegistry()
        reg.register(Omitted())
        self.assertEqual(run_all(load_fixture(FIXTURE), reg)[0].status, "failed")

    def test_duplicate_findings_rejected(self):
        class Duplicated(MockCppDetector):
            def detect(self, context, units):
                f = DetectorFinding(units[0].path, 1, "x", "x")
                return DetectorRun(self.detector_id, self.version, "completed",
                                   analyzed_files=(units[0].path,), findings=(f, f))
        reg = DetectorRegistry()
        reg.register(Duplicated())
        self.assertEqual(run_all(load_fixture(FIXTURE), reg)[0].status, "failed")

    def test_snapshot_drift_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "test.cpp").write_text("before", encoding="utf-8")
            context = load_fixture(root)
            (root / "test.cpp").write_text("after", encoding="utf-8")
            with self.assertRaises(ValueError):
                verify_fixture_unchanged(root, context)

    def test_runner_rejects_forged_snapshot_identity(self):
        original = load_fixture(FIXTURE)
        forged_request = ScanRequest(
            original.request.request_id, original.request.repository,
            original.request.commit, "0" * 64, original.request.target_id,
        )
        forged = ScanContext(forged_request, original.units)
        registry = DetectorRegistry()
        registry.register(MockCppDetector())
        with self.assertRaisesRegex(ValueError, "manifest does not match"):
            run_all(forged, registry)

    def test_cli_runs_two_mock_detectors_end_to_end(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            command = [sys.executable, "-m", "src.cli", "ohscan",
                       "--fixture-root", str(FIXTURE),
                       "--json-out", str(out / "smoke.json"),
                       "--md-out", str(out / "smoke.md")]
            process = subprocess.run(
                command, cwd=Path(__file__).resolve().parents[1],
                capture_output=True, text=True, check=False, timeout=20,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            result = json.loads((out / "smoke.json").read_text(encoding="utf-8"))
            self.assertEqual([run["tool"] for run in result["runs"]],
                             ["ohscanner.mock.cpp", "ohscanner.mock.interface"])
            self.assertEqual(result["validated_vulnerability"], 0)
            self.assertTrue((out / "smoke.md").is_file())

    def test_fixture_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "real.cpp").write_text("ok", encoding="utf-8")
            (root / "alias.cpp").symlink_to(root / "real.cpp")
            with self.assertRaises(ValueError):
                load_fixture(root)


if __name__ == "__main__":
    unittest.main()
