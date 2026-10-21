"""M2 integration contract: audited first-party source detector execution.

All Git fixtures are created locally. There is no external scanner dependency,
no exploitable payload, and no claim of confirmed vulnerabilities.
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from src.ohscanner.detectors.catalog import build_registry, catalog_metadata
from src.ohscanner.execution import run_reviewed_detectors, run_fixed_commit_scan

PROJECT = Path(__file__).resolve().parents[1]
ID = "ohscanner.example.cpp.copy-calls"


def git(repo, *args):
    done = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, check=True, text=True, timeout=20,
    )
    return done.stdout.strip()


class M2ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repository"
        self.repo.mkdir()
        git(self.repo, "init", "-q")
        git(self.repo, "config", "user.email", "ci@example.invalid")
        git(self.repo, "config", "user.name", "M2 CI")
        (self.repo / "src").mkdir()
        (self.repo / "src" / "copy.cpp").write_text(
            "void f(char* dst, char* src) { memcpy(dst, src, 10); }\n",
            encoding="utf-8",
        )
        (self.repo / "src" / "clean.cpp").write_text(
            "int safe() { return 7; }\n", encoding="utf-8"
        )
        (self.repo / "src" / "partial.cpp").write_text(
            "int malformed( { memcpy(dst, src, 10);\n", encoding="utf-8"
        )
        (self.repo / "src" / "bridge.ets").write_text(
            "function bridge(): number { return 1; }\n", encoding="utf-8"
        )
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "pinned fixture")
        self.commit = git(self.repo, "rev-parse", "HEAD")

    def execute(self):
        return run_fixed_commit_scan(
            self.repo, "fixture/m2-integration", self.commit, (".",),
            (ID,), self.root / "m2.json", self.root / "m2.md",
            allow_examples=True,
        )

    def test_allowlisted_example_runs_on_fixed_git_objects(self):
        result = self.execute()
        self.assertEqual(result["experiment_kind"], "first_party_detector_execution")
        self.assertEqual(result["commit"], self.commit)
        self.assertEqual(result["provenance"], "local_git_objects")
        self.assertEqual(result["detector_count"], 1)
        self.assertEqual(result["diagnostic_count"], 1)
        self.assertEqual(result["validated_vulnerability"], 0)
        self.assertEqual(result["status"], "completed_with_limitations")
        self.assertEqual(result["source_parsing"]["languages"], {"arkts": 1, "cpp": 3})
        self.assertIn({"id": "syntax_facts_v1", "version": "1.0.0",
                       "output_fact": "facts_v1"}, result["analysis_fact_providers"])
        run = result["detector_runs"][0]
        self.assertEqual(run["tool"], ID)
        self.assertEqual(run["status"], "completed")
        self.assertEqual(run["scope_files"], 2)
        self.assertEqual(run["diagnostics"][0]["severity"], "unassessed")
        self.assertEqual(run["diagnostics"][0]["evidence_type"], "syntax")
        self.assertEqual(run["diagnostics"][0]["file"], "src/copy.cpp")
        self.assertIn("INCOMPLETE COVERAGE", " ".join(run["limitations"]))
        coverage = result["detector_coverage"]["detectors"][ID]
        self.assertEqual(coverage["status"], "partial")
        self.assertEqual(coverage["applicable_files"], 3)
        self.assertEqual(coverage["analyzed_files"], ["src/clean.cpp", "src/copy.cpp"])
        self.assertEqual(coverage["unexamined"][0]["file"], "src/partial.cpp")
        self.assertTrue(coverage["unexamined"][0]["reason"].startswith("incomplete_ast"))
        obligations = coverage["evidence_obligations"][0]["obligations"]
        self.assertEqual({o["kind"] for o in obligations},
                         {"resolved_callee", "bounds_proof", "reachability"})
        self.assertTrue(all(o["status"] == "unknown" for o in obligations))
        self.assertEqual(json.loads((self.root / "m2.json").read_text()), result)
        self.assertIn("NOT validated vulnerabilities",
                      (self.root / "m2.md").read_text())

    def test_pinned_result_is_not_affected_by_worktree_modifications(self):
        before = self.execute()
        (self.repo / "src" / "copy.cpp").write_text(
            "void f() { return; }\n", encoding="utf-8"
        )
        after = self.execute()
        self.assertEqual(before["snapshot_sha256"], after["snapshot_sha256"])
        self.assertEqual(before["detector_runs"][0]["diagnostics"],
                         after["detector_runs"][0]["diagnostics"])

    def test_unapproved_and_duplicate_plugins_rejected(self):
        for ids, flag in (
            ((ID,), False),
            (("src.ohscanner.bad:Class",), True),
            ((ID, ID), True),
            ((), True),
        ):
            with self.subTest(ids=ids, flag=flag), self.assertRaises(ValueError):
                build_registry(ids, allow_examples=flag)
        self.assertEqual(catalog_metadata()[ID]["kind"], "example")

    def test_programmatic_reviewed_registry_works_without_cli_policy(self):
        registry = build_registry((ID,), allow_examples=True)
        result = run_reviewed_detectors(
            self.repo, "fixture/m2-integration", self.commit, (".",), registry
        )
        self.assertEqual(result["detector_runs"][0]["tool"], ID)

    def test_no_plugins_must_not_be_misreported_as_clean(self):
        from src.ohscanner.runner import DetectorRegistry
        with self.assertRaisesRegex(ValueError, "reviewed detector"):
            run_reviewed_detectors(
                self.repo, "fixture/m2-integration", self.commit,
                (".",), DetectorRegistry(),
            )

    def test_cli_requires_explicit_example_acknowledgment(self):
        args = [
            sys.executable, "-m", "src.cli", "ohscan-run",
            "--repo-dir", str(self.repo), "--repository", "fixture/m2-integration",
            "--commit", self.commit, "--detector", ID,
            "--json-out", str(self.root / "cli.json"),
            "--md-out", str(self.root / "cli.md"),
        ]
        denied = subprocess.run(
            args, cwd=PROJECT, capture_output=True, text=True, timeout=40
        )
        self.assertNotEqual(denied.returncode, 0)
        self.assertIn("--allow-example-detectors", denied.stderr)
        accepted = subprocess.run(
            args + ["--allow-example-detectors"],
            cwd=PROJECT, capture_output=True, text=True, timeout=40
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertEqual(json.loads((self.root / "cli.json").read_text())["commit"],
                         self.commit)

    def test_cli_rejects_moving_refs(self):
        args = [
            sys.executable, "-m", "src.cli", "ohscan-run",
            "--repo-dir", str(self.repo), "--repository", "fixture/m2-integration",
            "--commit", "HEAD", "--detector", ID, "--allow-example-detectors",
        ]
        process = subprocess.run(args, cwd=PROJECT, capture_output=True, text=True, timeout=40)
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("full lowercase Git commit SHA", process.stderr)

    def test_reports_from_other_repository_cannot_be_reused(self):
        report = self.execute()
        self.assertEqual(report["target_id"], "current-component:fixture/m2-integration")
        self.assertEqual(report["detector_runs"][0]["target_id"], report["target_id"])
        self.assertEqual(report["detector_runs"][0]["commit"], self.commit)

    def test_nonmatching_language_is_explicitly_not_applicable(self):
        (self.repo / "src" / "copy.cpp").unlink()
        (self.repo / "src" / "clean.cpp").unlink()
        (self.repo / "src" / "partial.cpp").unlink()
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "arkts only")
        new_commit = git(self.repo, "rev-parse", "HEAD")
        report = run_fixed_commit_scan(
            self.repo, "fixture/m2-integration", new_commit, (".",),
            (ID,), self.root / "arkts.json", self.root / "arkts.md",
            allow_examples=True,
        )
        coverage = report["detector_coverage"]["detectors"][ID]
        self.assertEqual(coverage["status"], "not_applicable")
        self.assertEqual(report["detector_runs"][0]["status"], "blocked")
        self.assertEqual(report["diagnostic_count"], 0)


if __name__ == "__main__":
    unittest.main()
