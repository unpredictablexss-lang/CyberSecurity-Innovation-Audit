"""Real Git-object M2 integration of teammate A's two unmodified candidate algorithms."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from src.ohscanner.contracts import DetectorRun, ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.catalog import build_registry, catalog_metadata
from src.ohscanner.detectors.cpp.m2_adapter import M2LifetimeDetector, M2SharedPtrRaceDetector
from src.ohscanner.execution import run_fixed_commit_scan
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "detectors" / "fixtures"
IDS = ("ohscanner.cpp.lifetime", "ohscanner.cpp.shared_ptr_race")


def git(directory, *args):
    return subprocess.run(
        ["git", "-C", str(directory), *args],
        capture_output=True, check=True, text=True, timeout=15,
    ).stdout.strip()


class M2AIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="oh-m2-a-")
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name) / "target"
        self.repo.mkdir()
        (self.repo / "src").mkdir()
        git(self.repo, "init", "-q")
        git(self.repo, "config", "user.email", "integration@example.invalid")
        git(self.repo, "config", "user.name", "M2-A CI")
        self.target = {
            "lifetime.cpp": FIX / "cpp_lifetime" / "vulnerable_unserialized.cpp",
            "race.cpp": FIX / "cpp_shared_ptr_race" / "vulnerable_non_atomic_shared_ptr.cpp",
            "safe.cpp": FIX / "cpp_lifetime" / "fixed_alias_rebind.cpp",
        }
        for name, path in self.target.items():
            (self.repo / "src" / name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
        (self.repo / "src" / "partial.cpp").write_text("int invalid( {\n", encoding="utf-8")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "immutable review fixtures")
        self.sha = git(self.repo, "rev-parse", "HEAD")

    def run_m2(self):
        return run_fixed_commit_scan(
            self.repo, "fixture/m2-a", self.sha, (".",), IDS,
            Path(self.tmp.name) / "report.json",
            Path(self.tmp.name) / "report.md",
        )

    def test_catalog_enables_only_explicit_research_detectors(self):
        registry = build_registry(IDS)
        self.assertEqual({item.detector_id for item in registry.detectors()}, set(IDS))
        self.assertEqual(catalog_metadata()[IDS[0]]["kind"], "research_candidate")
        with self.assertRaisesRegex(ValueError, "allow-example"):
            build_registry(("ohscanner.example.cpp.copy-calls",))

    def test_git_pipeline_keeps_candidate_uncertainty_and_coverage(self):
        report = self.run_m2()
        self.assertEqual(report["commit"], self.sha)
        self.assertEqual(report["detector_count"], 2)
        self.assertEqual(report["validated_vulnerability"], 0)
        self.assertEqual(report["status"], "completed_with_limitations")
        runs = {row["tool"]: row for row in report["detector_runs"]}
        self.assertEqual(set(runs), set(IDS))
        self.assertGreater(runs[IDS[0]]["diagnostic_count"], 0)
        self.assertGreater(runs[IDS[1]]["diagnostic_count"], 0)
        for detector_id in IDS:
            run = runs[detector_id]
            scope = report["detector_coverage"]["detectors"][detector_id]
            # Complete AST is only an entry prerequisite, not proof that the
            # narrow A rule can fully model every source file. Preserve a
            # blocked run and partially inspected files if semantics are unknown.
            self.assertIn(run["status"], ("completed", "blocked"))
            self.assertEqual(scope["status"], "partial")
            self.assertIn("src/partial.cpp", [item["file"] for item in scope["unexamined"]])
            self.assertGreaterEqual(
                len(scope["analyzed_files"]) + len(scope["partially_inspected_files"]), 1
            )
            self.assertTrue(
                all(name in scope["source_sha256"]
                    for name in ("src/lifetime.cpp", "src/race.cpp", "src/safe.cpp"))
            )
            self.assertTrue(all(d["severity"] == "unassessed" and d["confidence"] == "unassessed"
                                for d in run["diagnostics"]))
            self.assertTrue(scope["evidence_obligations"])
            self.assertTrue(all(item["analysis_status"] in ("analyzed", "partial")
                                for item in scope["evidence_obligations"]))
            for item in scope["evidence_obligations"]:
                self.assertEqual(item["source_sha256"], scope["source_sha256"][item["file"]])
                self.assertTrue(all(o["status"] == "unknown" for o in item["obligations"]))
        self.assertEqual(json.loads((Path(self.tmp.name)/"report.json").read_text()), report)

    def test_fixed_git_version_not_affected_by_worktree_edit(self):
        before = self.run_m2()
        (self.repo / "src" / "lifetime.cpp").write_text("int different() { return 0; }\n")
        after = self.run_m2()
        self.assertEqual(before["snapshot_sha256"], after["snapshot_sha256"])
        self.assertEqual(before["detector_runs"][0]["diagnostics"],
                         after["detector_runs"][0]["diagnostics"])

    def test_detector_internal_unknown_retains_completed_peer_and_partial_candidates(self):
        text1 = (FIX / "cpp_lifetime" / "vulnerable_unserialized.cpp").read_text()
        text2 = (FIX / "cpp_lifetime" / "incomplete_scope_unmodeled_owner.cpp").read_text()
        a = SourceUnit("a.cpp", "cpp", text1, hashlib.sha256(text1.encode()).hexdigest(), "complete")
        b = SourceUnit("b.cpp", "cpp", text2, hashlib.sha256(text2.encode()).hexdigest(), "complete")
        units = (a, b)
        ctx = ScanContext(
            ScanRequest("m2-a-partial", "fixture/m2-a", "fixture", snapshot_digest(units),
                        "current-component:fixture/m2-a"), units,
            {"ast": {a.path: {"parse_status": "complete"}, b.path: {"parse_status": "complete"}}},
        )
        registry = DetectorRegistry()
        registry.register(M2LifetimeDetector())
        reports, cover = run_all_with_coverage(ctx, registry)
        one = reports[0]
        details = cover["detectors"][IDS[0]]
        self.assertEqual(one.status, "blocked")
        self.assertTrue(one.diagnostics)
        self.assertEqual(details["status"], "partial")
        self.assertIn("a.cpp", details["analyzed_files"])
        self.assertIn("b.cpp", [x["file"] for x in details["unexamined"]])
        self.assertTrue(details["evidence_obligations"])

    def test_per_file_state_rejects_unsupported_fake_scope(self):
        # Normal execution may finish with only partial semantic coverage.
        run = DetectorRun("ohscanner.fake", "v1", "completed",
                          analyzed_files=("x.cpp",), file_outcomes=(("x.cpp", "partial"),))
        self.assertEqual(run.file_outcomes, (("x.cpp", "partial"),))
        with self.assertRaises(ValueError):
            DetectorRun("ohscanner.fake", "v1", "blocked", file_outcomes=(("../x.cpp", "partial"),))


if __name__ == "__main__":
    unittest.main()
