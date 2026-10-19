"""Contract v2 regression: source binding, consequence fields, version naming.

Contract v2 is breaking for two reasons (see
`docs/contracts/ohscanner_detector_contract_v2.md` §0): `source_sha256` is
required in the produced schema, and `diagnostic_id` now includes it, so v1 and
v2 IDs are not the same key space. Both properties are pinned below, together
with the rule that a v1 payload must come back *unbound* rather than being
handed a hash it never had.
"""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from src.benchmark.compare import (
    compare_normalized_reports, render_markdown as render_comparison_markdown,
)
from src.benchmark.historical import HistoricalSample
from src.benchmark.report_inputs import load_report_runs
from src.benchmark.tool_result import (
    ToolDiagnostic, ToolRunResult, render_markdown as render_run_markdown,
)
from src.ohscanner.contracts import (
    DetectorFinding, DetectorRun, ScanContext, ScanRequest, SourceUnit,
)
from src.ohscanner.detectors.interface.models import (
    IMPACT_BY_RULE, reviewed_consequence,
)
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage

SOURCE = "void handler() {\n  return;\n}\n"
HASH = hashlib.sha256(SOURCE.encode("utf-8")).hexdigest()
OTHER_SOURCE = "void handler() {\n  return; // same shape, different bytes\n}\n"


def source_unit(text=SOURCE, path="src/a.cpp", language="cpp"):
    return SourceUnit(path=path, language=language, text=text,
                      sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
                      parse_status="complete")


def scan_context(units=None):
    units = tuple(sorted(units or (source_unit(),), key=lambda unit: unit.path))
    request = ScanRequest("v2-regression", "fixture/v2-binding", "synthetic",
                          snapshot_digest(units), "current-component:fixture/v2-binding")
    return ScanContext(request, units, {"ast": {
        unit.path: {"functions": [], "calls": [], "variables": []} for unit in units}})


class FixedFindings:
    """Detector that returns exactly the findings it was given."""

    detector_id = "ohscanner.test.binding"
    version = "1.0.0"
    supported_languages = ("c", "cpp")
    required_facts = ()

    def __init__(self, findings):
        self._findings = tuple(findings)

    def detect(self, context, units):
        return DetectorRun(self.detector_id, self.version, "completed",
                           analyzed_files=tuple(unit.path for unit in units),
                           findings=self._findings)


class RaisingDetector(FixedFindings):
    detector_id = "ohscanner.test.raises"

    def detect(self, context, units):
        raise RuntimeError("synthetic failure")


class NotMyLanguage(FixedFindings):
    detector_id = "ohscanner.test.other-language"
    supported_languages = ("js",)


def finding(**overrides):
    fields = dict(file="src/a.cpp", line=2, rule_id="test.rule", message="candidate message")
    fields.update(overrides)
    return DetectorFinding(**fields)


def run_one(detector, units=None, context=None):
    registry = DetectorRegistry()
    registry.register(detector)
    reports, sidecar = run_all_with_coverage(context or scan_context(units), registry)
    return reports[0], sidecar["detectors"][detector.detector_id]


def expect_diagnostic_id(source_hash):
    digest = hashlib.sha256("|".join(
        (source_hash, "src/a.cpp", "2", "test.rule", "candidate message")
    ).encode("utf-8")).hexdigest()[:16]
    return FixedFindings.detector_id + ":" + digest


class SourceBindingTests(unittest.TestCase):
    def test_an_unset_hash_is_bound_by_the_runner_to_the_analyzed_unit(self):
        report, _coverage = run_one(FixedFindings([finding()]))
        self.assertEqual(report.schema_version, 2)
        self.assertEqual(len(report.diagnostics), 1)
        diagnostic = report.diagnostics[0]
        self.assertEqual(diagnostic.source_sha256, HASH)
        self.assertEqual(diagnostic.source_binding, "bound")
        # The ID carries the source revision: this is the value v2 changed.
        self.assertEqual(diagnostic.diagnostic_id, expect_diagnostic_id(HASH))

    def test_a_declared_hash_matching_the_unit_is_accepted_unchanged(self):
        report, _coverage = run_one(FixedFindings([finding(source_sha256=HASH)]))
        self.assertEqual(report.status, "completed")
        self.assertEqual(report.diagnostics[0].source_sha256, HASH)
        self.assertEqual(report.diagnostics[0].diagnostic_id, expect_diagnostic_id(HASH))

    def test_a_disagreeing_hash_is_refused_and_not_rewritten(self):
        stale = "0" * 64
        report, _coverage = run_one(FixedFindings([finding(source_sha256=stale)]))
        # Refusing the run is the point: neither substituting the unit hash nor
        # downgrading the finding to unbound would be honest.
        self.assertEqual(report.status, "failed")
        self.assertEqual(report.diagnostics, [])
        self.assertTrue(any("Detector failed: ValueError" in item
                            for item in report.limitations))
        self.assertNotIn(stale, json.dumps(report.to_dict()))

    def test_a_different_source_revision_yields_a_different_diagnostic_id(self):
        first, _coverage = run_one(FixedFindings([finding()]))
        second, _coverage = run_one(
            FixedFindings([finding()]), units=(source_unit(text=OTHER_SOURCE),))
        self.assertNotEqual(first.diagnostics[0].source_sha256,
                            second.diagnostics[0].source_sha256)
        self.assertNotEqual(first.diagnostics[0].diagnostic_id,
                            second.diagnostics[0].diagnostic_id)

    def test_a_line_outside_the_source_is_refused(self):
        report, _coverage = run_one(FixedFindings([finding(line=99)]))
        self.assertEqual(report.status, "failed")
        self.assertEqual(report.diagnostics, [])

    def test_v2_refuses_to_emit_a_diagnostic_without_a_source_revision(self):
        unbound = ToolDiagnostic(
            diagnostic_id="d1", provider="joern", evidence_type="syntax",
            file="src/f.cpp", line=3, column=None, rule_id="r", severity="warning",
            message="m")
        self.assertEqual(unbound.source_binding, "unbound")
        with self.assertRaisesRegex(ValueError, "requires a source SHA-256"):
            ToolRunResult(
                schema_version=2, run_id="r", tool="joern", tool_version="1",
                target_id="t", commit="c", scope_files=1, scope_loc=1,
                status="completed", elapsed_seconds=0.1, diagnostics=[unbound])

    def test_a_version_neither_one_nor_two_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unsupported schema_version"):
            ToolRunResult(
                schema_version=3, run_id="r", tool="joern", tool_version="1",
                target_id="t", commit="c", scope_files=0, scope_loc=0,
                status="completed", elapsed_seconds=0.1)

    def test_a_v1_payload_loads_unbound_but_is_not_given_a_hash(self):
        legacy = ToolDiagnostic(
            diagnostic_id="d1", provider="joern", evidence_type="syntax",
            file="src/f.cpp", line=3, column=None, rule_id="r", severity="warning",
            message="m")
        payload = ToolRunResult(
            schema_version=1, run_id="r", tool="joern", tool_version="1",
            target_id="t", commit="c", scope_files=1, scope_loc=1,
            status="completed", elapsed_seconds=0.1,
            diagnostics=[legacy]).to_dict()
        rendered = payload["diagnostics"][0]
        self.assertEqual(rendered["source_sha256"], "")
        self.assertEqual(rendered["source_binding"], "unbound")


class StatusMappingTests(unittest.TestCase):
    """v2 adds fields; it must not move the status semantics."""

    def test_completed_stays_completed(self):
        report, coverage = run_one(FixedFindings([finding()]))
        self.assertEqual((report.status, coverage["status"]), ("completed", "complete"))
        self.assertEqual(report.scope_files, 1)

    def test_a_failed_detector_is_failed_and_claims_no_scope(self):
        report, coverage = run_one(RaisingDetector([]))
        self.assertEqual((report.status, coverage["status"]), ("failed", "failed"))
        self.assertEqual(report.scope_files, 0)
        self.assertEqual(report.scope_loc, 0)

    def test_an_unsupported_language_is_not_applicable_not_a_miss(self):
        report, coverage = run_one(NotMyLanguage([]))
        self.assertEqual((report.status, coverage["status"]), ("blocked", "not_applicable"))
        self.assertEqual(coverage["applicable_files"], 0)
        self.assertEqual(report.scope_files, 0)
        self.assertTrue(any("not_applicable" in item for item in report.limitations))

    def test_an_empty_finding_list_is_not_reported_as_safety(self):
        report, _coverage = run_one(FixedFindings([]))
        self.assertEqual(report.diagnostics, [])
        self.assertTrue(any("does not establish vulnerability" in item
                            for item in report.limitations))


class ConsequenceFieldTests(unittest.TestCase):
    def test_a_payload_without_the_new_fields_still_normalizes(self):
        report, _coverage = run_one(FixedFindings([finding()]))
        diagnostic = report.diagnostics[0]
        self.assertIsNone(diagnostic.consequence_impact)
        self.assertIsNone(diagnostic.consequence_cwe)

    def test_mechanism_and_consequence_coexist_without_overwriting(self):
        report, _coverage = run_one(FixedFindings([finding(
            candidate_cwe="CWE-862", consequence_impact="information_disclosure",
            consequence_cwe="CWE-200")]))
        diagnostic = report.diagnostics[0]
        self.assertEqual(diagnostic.candidate_cwe, "CWE-862")
        self.assertEqual(diagnostic.consequence_impact, "information_disclosure")
        self.assertEqual(diagnostic.consequence_cwe, "CWE-200")
        body = render_run_markdown(report)
        self.assertIn("CWE-862", body)
        self.assertIn("CWE-200", body)
        self.assertIn("CWE (mechanism)", body)

    def test_an_empty_consequence_is_rejected_rather_than_meaning_unclassified(self):
        for constructor in (
            lambda: finding(consequence_impact="   "),
            lambda: ToolDiagnostic(
                diagnostic_id="d1", provider="p", evidence_type="syntax", file="src/f.cpp",
                line=1, column=None, rule_id="r", severity="warning", message="m",
                consequence_impact=""),
        ):
            with self.subTest(constructor=constructor):
                with self.assertRaisesRegex(ValueError, "non-empty"):
                    constructor()

    def test_a_malformed_consequence_cwe_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "consequence CWE"):
            finding(consequence_cwe="CWE-abc")

    def test_the_catalogue_is_what_refuses_an_unreviewed_consequence(self):
        self.assertIsNone(reviewed_consequence(None))
        self.assertIsNone(reviewed_consequence("unknown"))
        self.assertEqual(reviewed_consequence("boundary_bypass"), "boundary_bypass")
        with self.assertRaisesRegex(ValueError, "unreviewed consequence class"):
            reviewed_consequence("remote_code_execution")

    def test_the_public_schema_does_not_hardcode_the_consequence_whitelist(self):
        # A review list belongs to the detector's versioned model; the shared
        # schema only checks shape, so the catalogue is where rejection happens.
        item = finding(consequence_impact="a_class_the_catalogue_never_reviewed",
                       consequence_cwe="CWE-999")
        self.assertEqual(item.consequence_impact, "a_class_the_catalogue_never_reviewed")

    def test_an_unknown_rule_yields_no_consequence_class_at_all(self):
        # "unknown" is the catalogue saying it has no modelled consequence; it must
        # not travel to the schema as a value a consumer could sort as a category.
        self.assertNotIn("ipc.something.new", IMPACT_BY_RULE)
        self.assertIsNone(reviewed_consequence("unknown"))


class CrossVersionCompareTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def report_file(self, name, tool, version):
        diagnostic = ToolDiagnostic(
            diagnostic_id=tool + ":d", provider=tool, evidence_type="syntax",
            file="src/f.cpp", line=3, column=None, rule_id="r", severity="warning",
            message="m", source_sha256=HASH if version == 2 else "")
        payload = ToolRunResult(
            schema_version=version, run_id=tool + "-run", tool=tool, tool_version="1",
            target_id="seed", commit="c" * 40, scope_files=1, scope_loc=1,
            status="completed", elapsed_seconds=0.1,
            diagnostics=[diagnostic]).to_dict()
        path = self.root / (name + ".json")
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_a_mixed_version_comparison_names_the_version_split(self):
        left = self.report_file("left", "own_ast", 2)
        right = self.report_file("right", "joern", 1)
        result = compare_normalized_reports([left, right])
        self.assertTrue(result.schema_versions_mixed())
        self.assertEqual(result.schema_versions, {"own_ast": 2, "joern": 1})
        self.assertTrue(any("CROSS-VERSION COMPARISON" in item
                            for item in result.limitations))
        self.assertIn("CROSS-VERSION COMPARISON", render_comparison_markdown(result))
        self.assertTrue(result.to_dict()["schema_versions_mixed"])

    def test_a_same_version_comparison_says_nothing_about_versions(self):
        left = self.report_file("left", "own_ast", 2)
        right = self.report_file("right", "codeql", 2)
        result = compare_normalized_reports([left, right])
        self.assertFalse(result.schema_versions_mixed())
        self.assertFalse(any("CROSS-VERSION" in item for item in result.limitations))
        # Both versions are still named in the output, they just agree.
        self.assertIn("Schema versions: codeql=v2, own_ast=v2",
                      render_comparison_markdown(result))

    def test_a_v1_payload_still_compares_against_another_v1_payload(self):
        left = self.report_file("left", "joern", 1)
        right = self.report_file("right", "semgrep", 1)
        result = compare_normalized_reports([left, right])
        self.assertEqual([item.schema_version for item in result.summaries], [1, 1])


class ReportInputIntegrationTests(unittest.TestCase):
    """The saved-report loader is where v1 and v2 payloads actually meet."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.seed = HistoricalSample(
            schema_version=1, sample_id="seed", title="test seed", repository="repo",
            repo_url="https://example.com/repo", vulnerable_commit="a" * 40,
            fixed_commit="b" * 40, weakness="CWE-476", affected_files=["src/f.cpp"],
            affected_symbols=["target"], root_cause="test root cause",
            root_cause_group="null_deref")

    def normalized_report(self, version):
        diagnostic = ToolDiagnostic(
            diagnostic_id="own_ast:d", provider="own_ast", evidence_type="syntax",
            file="src/f.cpp", line=3, column=None, rule_id="r", severity="warning",
            message="m", candidate_cwe="CWE-862",
            source_sha256=HASH if version == 2 else "",
            consequence_impact="information_disclosure" if version == 2 else None,
            consequence_cwe="CWE-200" if version == 2 else None).to_dict()
        return {
            "schema_version": version, "run_id": "run", "tool": "own_ast",
            "tool_version": "test", "target_id": "seed", "commit": "a" * 40,
            "scope_files": 1, "scope_loc": 20, "status": "completed",
            "elapsed_seconds": 0.1, "diagnostics": [diagnostic],
            "limitations": ["syntactic evidence only"],
            # own_ast requires recorded complete parsing coverage for the scope.
            "parsing": [{"file": "src/f.cpp", "status": "complete"}],
        }

    def manifest(self, payload, revision="vulnerable"):
        report = self.root / f"{revision}.json"
        report.write_text(json.dumps(payload), encoding="utf-8")
        entry = {"sample_id": "seed", "revision": revision, "report": report.name,
                 "analyzed_files": ["src/f.cpp"]}
        path = self.root / "inputs.json"
        path.write_text(json.dumps({"schema_version": 1, "runs": [entry]}),
                        encoding="utf-8")
        return path

    def test_a_v2_saved_report_loads_without_dropping_the_versioned_fields(self):
        runs = load_report_runs(self.manifest(self.normalized_report(2)), [self.seed])
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0].candidates[0].file, "src/f.cpp")

    def test_a_v1_saved_report_still_loads(self):
        runs = load_report_runs(self.manifest(self.normalized_report(1)), [self.seed])
        self.assertEqual(len(runs), 1)

    def test_vulnerable_and_fixed_revisions_never_merge_into_one_run(self):
        # Evidence groups are bound per revision; a third label would silently
        # mix them, so it is refused rather than folded into one of the two.
        with self.assertRaisesRegex(ValueError, "unsupported revision"):
            load_report_runs(self.manifest(self.normalized_report(2), "safe"), [self.seed])


if __name__ == "__main__":
    unittest.main()
