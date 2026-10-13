import json
from pathlib import Path
import tempfile
import unittest

from src.benchmark.differential import (
    RootCauseObservation,
    build_patch_discrimination,
    render_patch_discrimination_markdown,
)
from src.benchmark.root_cause_matrix import ToolCandidate, classify_tool_hit
from src.benchmark.historical import HistoricalSample
from src.ohscanner.analysis import (
    AnalysisRunContext,
    RevisionAnalysis,
    assess_version_analyses,
    compare_revision_analyses,
)
from src.ohscanner.contracts import (
    DetectorFinding,
    DetectorRun,
    ScanContext,
    ScanRequest,
    SourceUnit,
)
from src.ohscanner.patch_obligations import load_patch_obligations
from src.ohscanner.readonly_facts import ReadOnlyFactView
from src.providers.base import AdapterContext
from src.providers.infer import InferAdapter
from scripts.run_infer_experiments import (
    build_analyze_command,
    build_build_command,
    build_capture_command,
)
from scripts.collect_build_context import collect_build_context


SHA = "a" * 64


def request(commit: str, request_id: str = "req") -> ScanRequest:
    return ScanRequest(
        request_id=request_id,
        repository="openharmony/commonlibrary_c_utils",
        commit=commit,
        snapshot_sha256=SHA,
        target_id="current-component:openharmony/commonlibrary_c_utils",
        profile_id="light-ast",
        provenance="git_object",
    )


def context(revision_role: str, *, complete: bool = True) -> AnalysisRunContext:
    return AnalysisRunContext(
        analysis_mode="revision_range",
        revision_role=revision_role,
        analysis_unit="translation_unit",
        build_profile="linux-host",
        include_status="complete" if complete else "partial",
        analyzed_files=("src/a.cpp",),
        source_snapshot_sha256=SHA,
        limitations=() if complete else ("partial include graph",),
    )


def revision(commit: str, role: str, *, finding: bool, complete: bool = True) -> RevisionAnalysis:
    run = DetectorRun(
        detector_id="ohscanner.cpp.lifetime",
        version="1.0.0-test",
        status="completed",
        analyzed_files=("src/a.cpp",),
        findings=(
            DetectorFinding(
                file="src/a.cpp",
                line=10,
                rule_id="root-instance-001",
                message="candidate",
                symbol="Node::Use",
            ),
        ) if finding else (),
    )
    return RevisionAnalysis(
        request=request(commit),
        revision_role=role,
        run_contexts={"ohscanner.cpp.lifetime": context(role, complete=complete)},
        detector_runs=(run,),
    )


class AnalysisModeTests(unittest.TestCase):
    def test_revision_comparison_reports_new_persistent_disappeared(self) -> None:
        baseline = revision("1" * 40, "baseline", finding=True)
        endpoint = revision("2" * 40, "endpoint", finding=True)
        result = compare_revision_analyses(
            baseline, endpoint, comparison_identity="root-instance-001"
        )
        self.assertEqual(result["rows"], [{
            "detector_id": "ohscanner.cpp.lifetime",
            "finding_identity": "src/a.cpp:10:root-instance-001",
            "state": "persistent",
        }])
        self.assertIn("does not prove", result["interpretation"])

    def test_incomplete_coverage_prevents_delta_claim(self) -> None:
        baseline = revision("1" * 40, "baseline", finding=False)
        endpoint = revision("2" * 40, "endpoint", finding=True, complete=False)
        result = compare_revision_analyses(
            baseline, endpoint, comparison_identity="root-instance-001"
        )
        self.assertEqual(result["rows"][0]["state"], "unknown")

    def test_version_assessment_preserves_unknown_and_possible(self) -> None:
        result = assess_version_analyses(
            [
                revision("1" * 40, "target", finding=True),
                revision("2" * 40, "control_fixed", finding=False),
                revision("3" * 40, "control_safe", finding=True, complete=False),
            ],
            root_instance_id="root-instance-001",
        )
        self.assertEqual(
            [row["status"] for row in result["rows"]],
            ["possibly_affected", "not_present", "unknown"],
        )


class ReadOnlyFactTests(unittest.TestCase):
    def test_source_and_syntax_facts_are_observed_without_call_graph_claims(self) -> None:
        unit = SourceUnit(
            path="src/a.cpp",
            language="cpp",
            text="int a() {\n  return 1;\n}\n",
            sha256=__import__("hashlib").sha256(
                b"int a() {\n  return 1;\n}\n"
            ).hexdigest(),
            parse_status="complete",
        )
        scan_context = ScanContext(
            request=request("1" * 40),
            units=(unit,),
            shared_facts={
                "syntax_facts": {
                    "src/a.cpp": {"functions": [], "calls": [], "guards": []}
                }
            },
        )
        facts = ReadOnlyFactView(scan_context)
        self.assertEqual(facts.get_source_context("src/a.cpp")["status"], "observed")
        self.assertEqual(facts.get_syntax_facts("src/a.cpp")["status"], "observed")
        self.assertEqual(facts.get_guard_facts("src/a.cpp")["status"], "unknown")
        self.assertEqual(facts.get_call_path("a", "b")["status"], "unknown")
        self.assertEqual(facts.get_coverage()["files"]["src/a.cpp"]["parse_status"], "complete")


class PatchObligationTests(unittest.TestCase):
    def test_load_patch_obligations_and_reject_development_holdout(self) -> None:
        payload = {
            "schema_version": 1,
            "sample_id": "sample-001",
            "root_instance_id": "root-001",
            "root_cause_group": "oob_write",
            "obligations": [{
                "obligation_id": "check-length",
                "statement": "Validate index against current element length.",
                "guard_relation": "guard dominates read and write",
                "effect": "prevents out-of-bounds element access",
                "evidence_refs": ["patch.diff"],
                "status": "verified",
            }],
            "development_participation": True,
            "holdout_eligible": False,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "obligations.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            loaded = load_patch_obligations(path)
            self.assertEqual(loaded.obligations[0].obligation_id, "check-length")
            payload["holdout_eligible"] = True
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "holdout-ineligible"):
                load_patch_obligations(path)


class DifferentialTests(unittest.TestCase):
    def observation(self, kind: str, status: str, *, complete: bool = True):
        return RootCauseObservation(
            case_kind=kind,
            status=status,
            analysis_coverage="complete" if complete else "incomplete",
            run_id=f"run-{kind}",
            source_sha256=SHA if status == "possible_hit" else None,
            match_basis="patch_region" if status == "possible_hit" else None,
            reason="" if complete else "partial analysis",
        )

    def test_vulnerable_only_and_control_hit(self) -> None:
        vulnerable_only = build_patch_discrimination(
            sample_id="sample-001",
            root_instance_id="root-001",
            root_cause_group="oob_write",
            observations=[
                self.observation("vulnerable", "possible_hit"),
                self.observation("fixed", "no_observed_candidate_shape"),
                self.observation("safe", "no_observed_candidate_shape"),
                self.observation("unrelated", "no_observed_candidate_shape"),
            ],
        )
        self.assertEqual(vulnerable_only.classification, "vulnerable_only")
        self.assertIn("not TP/FP/FN", render_patch_discrimination_markdown(vulnerable_only))

        control_hit = build_patch_discrimination(
            sample_id="sample-001",
            root_instance_id="root-001",
            root_cause_group="oob_write",
            observations=[
                self.observation("vulnerable", "possible_hit"),
                self.observation("fixed", "no_observed_candidate_shape"),
                self.observation("safe", "possible_hit"),
                self.observation("unrelated", "no_observed_candidate_shape"),
            ],
        )
        self.assertEqual(control_hit.classification, "control_hit")

    def test_incomplete_observation_is_unknown(self) -> None:
        result = build_patch_discrimination(
            sample_id="sample-001",
            root_instance_id="root-001",
            root_cause_group="lifetime_uaf",
            observations=[
                self.observation("vulnerable", "possible_hit"),
                self.observation("fixed", "no_observed_candidate_shape"),
                self.observation("safe", "no_observed_candidate_shape"),
                self.observation("unrelated", "unknown_incomplete_analysis", complete=False),
            ],
        )
        self.assertEqual(result.classification, "unknown")


class MatchBasisTests(unittest.TestCase):
    def sample(self) -> HistoricalSample:
        return HistoricalSample(
            schema_version=1,
            sample_id="sample-001",
            title="sample",
            repository="openharmony/example",
            repo_url="https://gitee.com/openharmony/example",
            vulnerable_commit="1" * 40,
            fixed_commit="2" * 40,
            weakness="CWE-787",
            affected_files=["src/a.cpp"],
            affected_symbols=["fn"],
            root_cause="unchecked index",
            source_refs=["https://example.invalid/patch"],
            cve=None,
            notes="",
            label_status="advisory_confirmed",
            root_cause_group="oob_write",
            evidence_level="patch",
            runtime_replay_status="not_run",
        )

    def test_match_basis_is_recorded_and_prefers_stronger_evidence(self) -> None:
        hit = classify_tool_hit(
            self.sample(),
            "tool",
            [
                ToolCandidate("src/a.cpp", symbol=None, line=1),
                ToolCandidate("src/a.cpp", symbol="fn", line=2, match_basis="guard_relation"),
            ],
        )
        self.assertEqual(hit.status, "possible_hit")
        self.assertEqual(hit.match_basis, "guard_relation")
        self.assertEqual(hit.evidence_count, 1)


class InferAdapterTests(unittest.TestCase):
    def test_infer_adapter_normalizes_symbolic_and_unknown_evidence(self) -> None:
        context_value = AdapterContext(
            run_id="infer-run",
            target_id="sample",
            commit="1" * 40,
            scope_files=1,
            scope_loc=10,
            elapsed_seconds=1.0,
            tool_version="1.2.0",
        )
        result = InferAdapter().normalize({
            "infer_version": "1.2.0",
            "bugs": [
                {
                    "bug_type": "NULL_DEREFERENCE",
                    "file": "src/a.cpp",
                    "line": 7,
                    "procedure": "fn",
                    "qualifier": "value is null",
                    "cwe": ["CWE-476"],
                },
                {
                    "bug_type": "CUSTOM_CHECK",
                    "file": "src/b.cpp",
                    "line": 9,
                    "message": "review",
                },
            ],
        }, context_value)
        self.assertEqual(result.diagnostic_count, 2)
        self.assertEqual(result.diagnostics[0].evidence_type, "symbolic")
        self.assertEqual(result.diagnostics[1].evidence_type, "unknown")
        self.assertEqual(result.diagnostics[0].candidate_cwe, "CWE-476")


class ArtifactContractTests(unittest.TestCase):
    def test_committed_research_sidecars_are_typed_as_non_results(self) -> None:
        root = Path(__file__).resolve().parents[1]
        obligations = sorted(
            (root / "benchmarks/historical/patch_obligations").glob("*.json")
        )
        self.assertGreaterEqual(len(obligations), 2)
        for path in obligations:
            self.assertTrue(load_patch_obligations(path).obligations)

        exclusions = json.loads(
            (root / "benchmarks/historical/research/candidate_exclusions_2026-10-13.json")
            .read_text(encoding="utf-8")
        )
        self.assertEqual(exclusions["status"], "excluded_unverified")
        self.assertTrue(exclusions["candidates"])

        queries = json.loads(
            (root / "scripts/joern_queries/root_cause_queries.json").read_text(encoding="utf-8")
        )
        self.assertEqual(queries["status"], "designed_not_executed")
        self.assertGreaterEqual(len(queries["queries"]), 4)

    def test_infer_research_commands_do_not_use_a_shell(self) -> None:
        infer = Path("/opt/infer/bin/infer")
        results = Path("/tmp/results")
        self.assertEqual(
            build_capture_command(infer, results, Path("/tmp/compile_commands.json")),
            [
                "/opt/infer/bin/infer", "capture", "--results-dir", "/tmp/results",
                "--compilation-database", "/tmp/compile_commands.json",
            ],
        )
        self.assertEqual(
            build_build_command(infer, results, ["make", "component"]),
            ["/opt/infer/bin/infer", "run", "--results-dir", "/tmp/results", "--", "make", "component"],
        )
        self.assertEqual(
            build_analyze_command(infer, results),
            ["/opt/infer/bin/infer", "analyze", "--results-dir", "/tmp/results"],
        )

    def test_build_context_sidecar_binds_compile_commands_and_macros(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "src/a.cpp").write_text("int a() { return 0; }\n", encoding="utf-8")
            compile_commands = root / "compile_commands.json"
            compile_commands.write_text(json.dumps([
                {
                    "directory": str(root),
                    "file": "src/a.cpp",
                    "arguments": ["clang++", "-DTEST=1", "-UDEBUG", "-c", "src/a.cpp"],
                }
            ]), encoding="utf-8")
            result = collect_build_context(
                compile_commands=compile_commands,
                source_root=root,
                analysis_mode="snapshot",
                revision_role="target",
                analysis_unit="translation_unit",
                build_profile="linux-host",
                include_status="complete",
            )
            self.assertEqual(result["tu_count"], 1)
            self.assertEqual(result["context"]["analyzed_files"], ["src/a.cpp"])
            self.assertRegex(result["context"]["compile_commands_sha256"], r"^[a-f0-9]{64}$")
            self.assertRegex(result["context"]["macro_profile_sha256"], r"^[a-f0-9]{64}$")


if __name__ == "__main__":
    unittest.main()
