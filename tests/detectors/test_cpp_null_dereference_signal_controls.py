from __future__ import annotations

import hashlib
import json
import time
import unittest
from pathlib import Path
from unittest import mock

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage


ROOT = Path(__file__).resolve().parents[2]
CONTROL_ROOT = ROOT / "research" / "tests" / "a_null_02_controls"
MANIFEST_PATH = CONTROL_ROOT / "control_manifest.json"


def make_detector():
    from src.ohscanner.detectors.cpp.null_dereference_detector import (
        NullDereferenceDetector,
    )

    return NullDereferenceDetector()


def git_blob_sha1(data: bytes) -> str:
    header = b"blob " + str(len(data)).encode("ascii") + b"\0"
    return hashlib.sha1(header + data).hexdigest()


def make_unit(
    path: str,
    text: str,
    *,
    language: str = "cpp",
    parse_status: str = "complete",
) -> SourceUnit:
    return SourceUnit(
        path=path,
        language=language,
        text=text,
        sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        parse_status=parse_status,
    )


def make_context(units, *, with_blob_ids: bool = False):
    shared_facts = {}
    if with_blob_ids:
        shared_facts["source_blob_oid"] = {
            unit.path: git_blob_sha1(unit.text.encode("utf-8")) for unit in units
        }
    request = ScanRequest(
        request_id="test-fixture:a-null-02-controls",
        repository="fixture/ohscanner-null-controls",
        commit="synthetic-a-null-02",
        snapshot_sha256=snapshot_digest(units),
        target_id="current-component:fixture/ohscanner-null-controls",
        profile_id="fixture-no-build",
        provenance="fixture",
    )
    return ScanContext(request=request, units=units, shared_facts=shared_facts)


class NullDereferenceSignalControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        cls.units = tuple(
            sorted(
                (
                    make_unit(
                        item["path"],
                        (ROOT / item["path"]).read_text(encoding="utf-8"),
                    )
                    for item in cls.manifest["units"]
                ),
                key=lambda unit: unit.path,
            )
        )
        cls.context = make_context(cls.units)
        cls.detector = make_detector()

    def test_control_manifest_binds_all_four_categories_and_source_hashes(self) -> None:
        categories = {}
        for case in self.manifest["cases"]:
            categories.setdefault(case["category"], []).append(case)
        self.assertEqual(set(categories), {"positive", "fixed", "safe", "unrelated"})
        self.assertTrue(all(len(items) >= 2 for items in categories.values()))
        self.assertEqual(len(self.units), 19)
        by_path = {unit.path: unit for unit in self.units}
        for item in self.manifest["units"]:
            data = (ROOT / item["path"]).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), item["sha256"])
            self.assertEqual(git_blob_sha1(data), item["git_blob_sha1"])
            self.assertEqual(len(data), item["byte_length"])
            self.assertEqual(by_path[item["path"]].sha256, item["sha256"])

    def test_each_control_matches_expected_signal_and_coverage(self) -> None:
        cases = {item["fixture"]: item for item in self.manifest["cases"]}
        for unit in self.units:
            fixture = unit.path.rsplit("/", 1)[-1]
            case = cases[fixture]
            with self.subTest(fixture=fixture, category=case["category"]):
                run = self.detector.detect(self.context, (unit,))
                self.assertEqual(dict(run.file_outcomes), {unit.path: case["expected_coverage"]})
                self.assertEqual(len(run.findings), case["expected_finding_count"])
                for finding in run.findings:
                    self.assertEqual(finding.source_sha256, unit.sha256)
                    self.assertEqual(finding.rule_version, "1.2.0")
                    self.assertEqual(
                        finding.rule_lineage_id,
                        "A-NULL-01:ohcpp-null-dereference-candidate",
                    )
                    self.assertTrue(finding.symbol_identity)
                    self.assertRegex(finding.ast_fingerprint, r"^[0-9a-f]{64}$")
                    self.assertEqual(finding.identity_quality, "complete")
                    self.assertIn("candidate/unassessed", finding.message)
                    self.assertIn(
                        "guard_relation=" + case["guard_relation"],
                        finding.message,
                    )
                    if case["error_path"] != "not_applicable":
                        self.assertIn(
                            "error_path=" + case["error_path"],
                            finding.message,
                        )
                    self.assertIsNone(finding.consequence_impact)
                    self.assertIsNone(finding.consequence_cwe)
                if case["expected_finding_count"] == 0:
                    joined = "\n".join(run.limitations).lower()
                    self.assertIn("not a safe verdict", joined)
                    self.assertNotIn("is safe", joined)

    def test_combined_controls_keep_candidates_and_negative_controls_quiet(self) -> None:
        run = self.detector.detect(self.context, self.units)
        outcomes = dict(run.file_outcomes)
        self.assertEqual(run.status, "blocked")
        self.assertEqual(
            {
                state: sum(value == state for value in outcomes.values())
                for state in ("complete", "partial", "failed", "not_analyzed")
            },
            {"complete": 18, "partial": 1, "failed": 0, "not_analyzed": 0},
        )
        self.assertEqual(len(run.findings), 6)
        positive_paths = {
            item["path"]
            for item in self.manifest["units"]
            if next(case for case in self.manifest["cases"] if case["fixture"] == item["path"].rsplit("/", 1)[-1])["category"] == "positive"
        }
        self.assertEqual({finding.file for finding in run.findings}, positive_paths)

    def test_nothrow_allocation_source_and_fixed_guard_are_modeled(self) -> None:
        positive = make_unit(
            "controls/positive_nothrow_allocation.cpp",
            "int positive_nothrow_allocation() {\n"
            "    int *value = new (std::nothrow) int;\n"
            "    return *value;\n"
            "}\n",
        )
        positive_run = self.detector.detect(make_context((positive,)), (positive,))
        self.assertEqual(len(positive_run.findings), 1)
        self.assertIn(
            "null_source=nothrow_allocation_may_be_null",
            positive_run.findings[0].message,
        )
        self.assertEqual(positive_run.findings[0].rule_version, "1.2.0")

        fixed = make_unit(
            "controls/fixed_nothrow_allocation_guard.cpp",
            "int fixed_nothrow_allocation_guard() {\n"
            "    int *value = new (std::nothrow) int;\n"
            "    if (value == nullptr) {\n"
            "        return -1;\n"
            "    }\n"
            "    return *value;\n"
            "}\n",
        )
        fixed_run = self.detector.detect(make_context((fixed,)), (fixed,))
        self.assertEqual(fixed_run.findings, ())
        self.assertEqual(dict(fixed_run.file_outcomes), {fixed.path: "complete"})

    def test_partial_failed_and_not_analyzed_fail_closed_without_safety_claims(self) -> None:
        partial_text = "int partial_read(int *p) {\n    return *p;\n}\n"
        partial = make_unit("controls/partial.cpp", partial_text, parse_status="partial")
        partial_run = self.detector.detect(make_context((partial,)), (partial,))
        self.assertEqual(dict(partial_run.file_outcomes), {partial.path: "partial"})
        self.assertEqual(partial_run.status, "blocked")
        self.assertTrue(partial_run.findings)

        malformed = make_unit(
            "controls/malformed.cpp",
            "int malformed_read(int *p { return *p; }\n",
            parse_status="partial",
        )
        malformed_run = self.detector.detect(make_context((malformed,)), (malformed,))
        self.assertEqual(dict(malformed_run.file_outcomes), {malformed.path: "partial"})
        self.assertEqual(malformed_run.status, "blocked")
        self.assertTrue(
            any("source_syntax_malformed" in item for item in malformed_run.limitations)
        )

        failed = make_unit(
            "controls/failed.cpp",
            "int failed_read(int *p) { return *p;\n",
            parse_status="failed",
        )
        failed_run = self.detector.detect(make_context((failed,)), (failed,))
        self.assertEqual(dict(failed_run.file_outcomes), {failed.path: "failed"})
        self.assertEqual(failed_run.status, "failed")
        self.assertEqual(failed_run.findings, ())

        unsupported = make_unit(
            "controls/unrelated.js",
            "function read(value) { return value; }\n",
            language="js",
        )
        unsupported_run = self.detector.detect(make_context((unsupported,)), (unsupported,))
        self.assertEqual(dict(unsupported_run.file_outcomes), {unsupported.path: "not_analyzed"})
        self.assertEqual(unsupported_run.status, "blocked")
        self.assertEqual(unsupported_run.findings, ())
        for run in (partial_run, malformed_run, failed_run, unsupported_run):
            joined = "\n".join(run.limitations).lower()
            self.assertNotIn("is safe", joined)
            self.assertNotIn("no vulnerability", joined)
            self.assertNotIn("expected miss", joined)

    def test_duplicate_identity_is_deduplicated_without_message_forgery(self) -> None:
        unit = make_unit(
            "controls/duplicate.cpp",
            "int duplicate(int *p) { return *p + *p; }\n",
        )
        run = self.detector.detect(make_context((unit,)), (unit,))
        self.assertEqual(len(run.findings), 1)

        registry = DetectorRegistry()
        registry.register(self.detector)
        reports, _sidecar = run_all_with_coverage(make_context((unit,), with_blob_ids=True), registry)
        self.assertEqual(reports[0].diagnostic_count, 1)
        identity = reports[0].diagnostics[0].finding_identity
        self.assertEqual(identity["source_binding"]["status"], "bound")
        self.assertEqual(identity["source_binding"]["source_blob_oid"], git_blob_sha1(unit.text.encode("utf-8")))
        self.assertEqual(identity["source_binding"]["source_sha256"], unit.sha256)
        self.assertIsNotNone(identity["stable"]["id"])

    def test_output_identity_is_stable_across_replays(self) -> None:
        first = self.detector.detect(self.context, self.units)
        second = self.detector.detect(self.context, self.units)
        self.assertEqual(first, second)
        self.assertEqual(repr(first), repr(second))

    def test_maximum_unit_input_is_fail_closed(self) -> None:
        from src.ohscanner.detectors.cpp import null_dereference_detector as module

        text = "int input_limit_control() { return 0; }\n"
        oversized_text = text * ((module.MAX_UNIT_BYTES // len(text)) + 1)
        unit = make_unit("controls/oversized.cpp", oversized_text)
        run = self.detector.detect(make_context((unit,)), (unit,))
        self.assertEqual(dict(run.file_outcomes), {unit.path: "not_analyzed"})
        self.assertEqual(run.status, "blocked")
        self.assertEqual(run.findings, ())
        self.assertTrue(any("input_limit_unit_exceeded" in item for item in run.limitations))

    def test_total_input_budget_is_enforced_without_dropping_coverage(self) -> None:
        from src.ohscanner.detectors.cpp import null_dereference_detector as module

        text = "int bounded_input() { return 0; }\n" * 2000
        units = (
            make_unit("controls/budget_a.cpp", text),
            make_unit("controls/budget_b.cpp", text),
        )
        with mock.patch.object(module, "MAX_TOTAL_BYTES", len(text.encode("utf-8"))):
            run = self.detector.detect(make_context(units), units)
        self.assertEqual(
            dict(run.file_outcomes),
            {units[0].path: "complete", units[1].path: "not_analyzed"},
        )
        self.assertEqual(run.status, "blocked")
        self.assertTrue(any("input_limit_total_exceeded" in item for item in run.limitations))

    def test_bounded_analysis_has_a_meaningful_wall_time_regression(self) -> None:
        body = "".join(
            f"int perf_control_{index}(int value) {{ return value + {index}; }}\n"
            for index in range(2500)
        )
        unit = make_unit("controls/performance.cpp", body)
        self.assertGreater(len(unit.text.encode("utf-8")), 100_000)
        started = time.perf_counter()
        run = self.detector.detect(make_context((unit,)), (unit,))
        elapsed = time.perf_counter() - started
        self.assertEqual(dict(run.file_outcomes), {unit.path: "complete"})
        self.assertEqual(run.findings, ())
        self.assertLess(elapsed, 5.0, f"bounded detector exceeded wall limit: {elapsed:.3f}s")


if __name__ == "__main__":
    unittest.main()
