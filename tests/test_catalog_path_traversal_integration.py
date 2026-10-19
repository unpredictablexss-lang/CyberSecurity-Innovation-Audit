from __future__ import annotations

import hashlib
import unittest

from src.benchmark.tool_result import ToolDiagnostic, ToolRunResult
from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.catalog import (
    build_registry,
    catalog_metadata,
    default_detector_ids,
    resolve_detector_ids,
)
from src.ohscanner.detectors.cpp.path_traversal_detector import (
    CppPathTraversalDetector,
    RULE_ID,
    RULE_VERSION,
)
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.runner import run_all_with_coverage


DETECTOR_ID = "ohscanner.cpp.path_traversal"
POSITIVE_SOURCE = """struct DataShareValuesBucket {
    std::string GetString(const std::string &) const;
};

void load_picture(const DataShareValuesBucket &bucket, const std::string &root)
{
    auto field = bucket.GetString("picture");
    std::string path = root + "/" + field;
    open(path.c_str(), O_RDONLY);
}
"""


def source_unit(text: str, language: str = "cpp") -> SourceUnit:
    return SourceUnit(
        path="src/catalog_integration.cpp" if language == "cpp" else "src/catalog_integration.js",
        language=language,
        text=text,
        sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        parse_status="complete",
    )


def scan_context(*units: SourceUnit) -> ScanContext:
    ordered = tuple(sorted(units, key=lambda item: item.path))
    return ScanContext(
        request=ScanRequest(
            request_id="catalog:path-traversal-integration",
            repository="fixture/catalog-integration",
            commit="b" * 40,
            snapshot_sha256=snapshot_digest(ordered),
            target_id="current-component:fixture/catalog-integration",
            profile_id="fixture-no-build",
            provenance="fixture",
        ),
        units=ordered,
    )


class CatalogPathTraversalIntegrationTests(unittest.TestCase):
    def test_research_candidate_is_explicit_and_conservatively_not_default(self) -> None:
        metadata = catalog_metadata()[DETECTOR_ID]
        self.assertEqual(metadata["kind"], "research_candidate")
        self.assertFalse(metadata["default_enabled"])
        self.assertTrue(metadata["admission_reason"].startswith("explicit_selection_required:"))
        self.assertNotIn(DETECTOR_ID, default_detector_ids())
        self.assertEqual(resolve_detector_ids([DETECTOR_ID]), (DETECTOR_ID,))

    def test_explicit_selection_builds_registry_and_metadata_is_detached(self) -> None:
        registry = build_registry([DETECTOR_ID])
        detector = registry.detectors()[0]
        self.assertIsInstance(detector, CppPathTraversalDetector)
        self.assertEqual(detector.detector_id, DETECTOR_ID)
        self.assertEqual(detector.version, RULE_VERSION)
        self.assertEqual(detector.supported_languages, ("c", "cpp"))
        self.assertEqual(detector.required_facts, ())
        self.assertNotIn("factory", catalog_metadata()[DETECTOR_ID])

    def test_runner_applies_only_to_c_and_cpp_units(self) -> None:
        reports, coverage = run_all_with_coverage(
            scan_context(source_unit("const answer = 42;\n", "js")),
            build_registry([DETECTOR_ID]),
        )
        self.assertEqual(reports[0].status, "blocked")
        self.assertIn("not_applicable", reports[0].limitations[0])
        self.assertEqual(coverage["detectors"][DETECTOR_ID]["status"], "not_applicable")
        self.assertEqual(coverage["detectors"][DETECTOR_ID]["applicable_files"], 0)

    def test_explicit_candidate_emits_source_bound_v2_and_fails_identity_closed(self) -> None:
        unit = source_unit(POSITIVE_SOURCE)
        context = scan_context(unit)
        reports, coverage = run_all_with_coverage(
            context, build_registry([DETECTOR_ID])
        )
        report = reports[0]
        self.assertEqual(report.schema_version, 2)
        self.assertEqual(report.tool, DETECTOR_ID)
        self.assertEqual(len(report.diagnostics), 1)
        diagnostic = report.diagnostics[0]
        self.assertEqual(diagnostic.provider, DETECTOR_ID)
        self.assertEqual(diagnostic.rule_id, RULE_ID)
        self.assertEqual(diagnostic.source_sha256, unit.sha256)
        self.assertEqual(diagnostic.severity, "unassessed")
        self.assertEqual(diagnostic.confidence, "unassessed")
        self.assertIsNone(diagnostic.finding_identity_id)
        self.assertIsNone(diagnostic.occurrence_id)
        self.assertEqual(diagnostic.finding_identity["stable"]["status"], "unknown")
        self.assertEqual(diagnostic.finding_identity["occurrence"]["status"], "unknown")
        self.assertIn(diagnostic.diagnostic_id, diagnostic.finding_identity["historical_ids"])
        binding = coverage["detectors"][DETECTOR_ID]["evidence_obligations"][0]["source_binding"]
        self.assertEqual(binding["repository"], "fixture/catalog-integration")
        self.assertEqual(binding["commit"], "b" * 40)
        self.assertEqual(binding["snapshot_sha256"], context.request.snapshot_sha256)
        self.assertEqual(binding["detector_id"], DETECTOR_ID)
        self.assertEqual(binding["detector_version"], RULE_VERSION)
        self.assertEqual(binding["rule_id"], RULE_ID)
        self.assertEqual(binding["source_sha256"], unit.sha256)

    def test_legacy_v1_remains_read_only_and_unbound(self) -> None:
        legacy_diagnostic = ToolDiagnostic(
            diagnostic_id="legacy:unchanged",
            provider="legacy-tool",
            evidence_type="syntax",
            file="src/legacy.cpp",
            line=1,
            column=None,
            rule_id="legacy-rule",
            severity="warning",
            message="legacy message",
        )
        legacy = ToolRunResult(
            schema_version=1,
            run_id="legacy:unchanged",
            tool="legacy-tool",
            tool_version="legacy",
            target_id="historical-target",
            commit="c" * 40,
            scope_files=1,
            scope_loc=1,
            status="completed",
            elapsed_seconds=0.0,
            diagnostics=(legacy_diagnostic,),
            limitations=("legacy v1 read-only compatibility",),
            parsing=(),
        )
        payload = legacy.to_dict()
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["diagnostics"][0]["source_sha256"], "")
        self.assertIsNone(payload["diagnostics"][0].get("finding_identity_id"))
        self.assertIsNone(payload["diagnostics"][0].get("finding_identity"))
        self.assertEqual(legacy_diagnostic.source_binding, "unbound")


if __name__ == "__main__":
    unittest.main()
