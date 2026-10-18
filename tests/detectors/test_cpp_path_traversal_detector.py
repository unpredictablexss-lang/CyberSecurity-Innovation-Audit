from __future__ import annotations

import hashlib
import unittest
from pathlib import Path
from unittest.mock import patch

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.cpp.path_traversal_detector import (
    CppPathTraversalDetector,
    RULE_ID,
    RULE_VERSION,
)
from src.ohscanner.fixture import snapshot_digest


FIXTURES = Path(__file__).parent / "fixtures" / "cpp_path_traversal"


def make_unit(path: Path, parse_status: str = "complete") -> SourceUnit:
    text = path.read_text(encoding="utf-8")
    return SourceUnit(
        path="tests/detectors/fixtures/cpp_path_traversal/" + path.name,
        language="cpp",
        text=text,
        sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        parse_status=parse_status,
    )


def make_context(*units: SourceUnit) -> ScanContext:
    ordered = tuple(sorted(units, key=lambda item: item.path))
    return ScanContext(
        request=ScanRequest(
            request_id="test:cpp-path-traversal",
            repository="fixture/ohscanner-path-flow",
            commit="4" * 40,
            snapshot_sha256=snapshot_digest(ordered),
            target_id="current-component:fixture/ohscanner-path-flow",
            profile_id="fixture-no-build",
            provenance="fixture",
        ),
        units=ordered,
    )


class CppPathTraversalDetectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.detector = CppPathTraversalDetector()

    def run_fixture(self, name: str, parse_status: str = "complete"):
        unit = make_unit(FIXTURES / name, parse_status)
        return self.detector.detect(make_context(unit), (unit,)), unit

    def test_identity_and_positive_file_operation_controls(self) -> None:
        self.assertEqual(self.detector.detector_id, "ohscanner.cpp.path_traversal")
        self.assertEqual(self.detector.version, RULE_VERSION)
        for name, sinks in (
            ("positive_read.cpp", {"open"}),
            ("positive_write_delete.cpp", {"creat", "unlink"}),
            ("bounded_return_helper.cpp", {"open"}),
        ):
            run, _ = self.run_fixture(name)
            self.assertEqual(run.status, "completed")
            self.assertEqual({item.rule_id for item in run.findings}, {RULE_ID})
            self.assertEqual({item.symbol for item in run.findings}, sinks)
            for finding in run.findings:
                self.assertEqual(finding.candidate_cwe, "CWE-22")
                self.assertEqual(finding.rule_version, RULE_VERSION)
                self.assertEqual(finding.source_sha256, make_unit(FIXTURES / name).sha256)
                self.assertEqual(finding.identity_quality, "partial")

    def test_fixture_manifest_hashes_and_categories(self) -> None:
        import json

        manifest = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema_version"], "cpp-path-traversal-dev-fixtures-v1")
        self.assertIn("not product reproductions", manifest["purpose"])
        self.assertEqual(
            {item["category"] for item in manifest["cases"]},
            {"positive", "fixed", "safe", "unrelated", "unknown"},
        )
        for item in manifest["cases"]:
            data = (FIXTURES / item["fixture"]).read_bytes()
            self.assertEqual(len(data), item["byte_length"], item["fixture"])
            self.assertEqual(hashlib.sha256(data).hexdigest(), item["sha256"], item["fixture"])
    def test_containment_basename_and_allowlist_controls(self) -> None:
        for name in (
            "fixed_basename.cpp",
            "fixed_canonical_containment.cpp",
            "fixed_literal_allowlist.cpp",
        ):
            run, _ = self.run_fixture(name)
            self.assertEqual(run.status, "completed", name)
            self.assertEqual(run.findings, (), name)

    def test_no_source_no_sink_and_unrelated_api_are_not_candidates(self) -> None:
        for name in ("unrelated_same_api_name.cpp", "no_file_sink.cpp"):
            run, _ = self.run_fixture(name)
            self.assertEqual(run.status, "completed", name)
            self.assertEqual(run.findings, (), name)

    def test_unresolved_cross_function_and_partial_parse_remain_unknown(self) -> None:
        cross, _ = self.run_fixture("cross_function_unknown.cpp")
        external, _ = self.run_fixture("external_wrapper_unknown.cpp")
        partial, _ = self.run_fixture("partial_parse.cpp", "partial")
        macro, _ = self.run_fixture("macro_unknown.cpp")
        self.assertEqual(cross.status, "blocked")
        self.assertEqual(cross.findings, ())
        self.assertIn("cross-file calls remain unknown", " ".join(cross.limitations))
        self.assertEqual(external.status, "blocked")
        self.assertEqual(external.findings, ())
        self.assertIn("unresolved external call", " ".join(external.limitations))
        self.assertEqual(partial.status, "blocked")
        self.assertEqual(partial.findings, ())
        self.assertIn("parse_status=partial", " ".join(partial.limitations))
        self.assertEqual(macro.status, "blocked")
        self.assertEqual(macro.findings, ())
        self.assertIn("preprocessor macros", " ".join(macro.limitations))

    def test_candidate_requires_file_sink_not_path_concatenation_alone(self) -> None:
        unit = SourceUnit(
            path="tests/detectors/fixtures/cpp_path_traversal/path_only.cpp",
            language="cpp",
            text=(
                "struct DataShareValuesBucket { std::string GetString(const std::string &) const; };\n"
                "std::string make(const DataShareValuesBucket &b, const std::string &root) {\n"
                "auto value = b.GetString(\"field\"); return root + \"/\" + value; }\n"
            ),
            sha256=hashlib.sha256((
                "struct DataShareValuesBucket { std::string GetString(const std::string &) const; };\n"
                "std::string make(const DataShareValuesBucket &b, const std::string &root) {\n"
                "auto value = b.GetString(\"field\"); return root + \"/\" + value; }\n"
            ).encode("utf-8")).hexdigest(),
            parse_status="complete",
        )
        run = self.detector.detect(make_context(unit), (unit,))
        self.assertEqual(run.status, "completed")
        self.assertEqual(run.findings, ())

    def test_budget_and_unexpected_analysis_failures_fail_closed(self) -> None:
        text = "int value;" + " " * (1024 * 1024)
        oversized = SourceUnit(
            path="tests/detectors/fixtures/cpp_path_traversal/oversized.cpp",
            language="cpp",
            text=text,
            sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        )
        run = self.detector.detect(make_context(oversized), (oversized,))
        self.assertEqual(run.status, "failed")
        self.assertEqual(run.findings, ())

        unit = make_unit(FIXTURES / "positive_read.cpp")
        with patch(
            "src.ohscanner.detectors.cpp.path_traversal_detector._analyze_unit",
            side_effect=RuntimeError("unexpected parser failure"),
        ):
            failed_closed = self.detector.detect(make_context(unit), (unit,))
        self.assertEqual(failed_closed.status, "blocked")
        self.assertEqual(failed_closed.findings, ())
        self.assertIn("RuntimeError", " ".join(failed_closed.limitations))


if __name__ == "__main__":
    unittest.main()
