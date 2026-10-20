"""M1.5 regression: offline partial clone, AST coverage, minimal evidence facts."""

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from src.ohscanner.contracts import (
    DetectorFinding, DetectorRun, EvidenceObligation,
    ScanContext, ScanRequest, SourceUnit,
)
from src.ohscanner.facts import build_syntax_facts
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.git_source import load_git_sources
from src.ohscanner.mocks import MockCppDetector
from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage


def _git(*args):
    return subprocess.run(["git", *[str(v) for v in args]],
                          check=True, capture_output=True, text=True, timeout=25).stdout.strip()


class OfflineGitTests(unittest.TestCase):
    def test_promisor_clone_never_fetches_missing_blob(self):
        with tempfile.TemporaryDirectory(prefix="m15-offline-") as tmp:
            root = Path(tmp)
            upstream = root / "upstream"
            upstream.mkdir()
            _git("-C", upstream, "init", "-q")
            _git("-C", upstream, "config", "user.name", "M1.5 CI")
            _git("-C", upstream, "config", "user.email", "ci@example.invalid")
            _git("-C", upstream, "config", "uploadpack.allowFilter", "true")
            (upstream / "sample.cpp").write_text(
                "int answer() { return 42; }\n", encoding="utf-8"
            )
            _git("-C", upstream, "add", "-A")
            _git("-C", upstream, "commit", "-qm", "source")
            commit = _git("-C", upstream, "rev-parse", "HEAD")
            partial = root / "partial"
            _git("clone", "--no-checkout", "--filter=blob:none",
                 upstream.as_uri(), partial)
            self.assertEqual(_git("-C", partial, "config", "--get",
                                  "remote.origin.promisor"), "true")
            trace = root / "read.trace"
            with patch.dict(os.environ, {"GIT_TRACE": str(trace)}):
                with self.assertRaisesRegex(ValueError, "missing_local_git_object"):
                    load_git_sources(partial, commit)
            log = trace.read_text(encoding="utf-8", errors="replace").lower()
            self.assertNotIn(" fetch origin", log)
            self.assertNotIn("upload-pack", log)
            self.assertNotIn("git-remote-", log)

    def test_complete_local_git_repo_still_indexes(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _git("-C", repo, "init", "-q")
            _git("-C", repo, "config", "user.name", "M1.5 CI")
            _git("-C", repo, "config", "user.email", "ci@example.invalid")
            (repo / "safe.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
            _git("-C", repo, "add", "-A")
            _git("-C", repo, "commit", "-qm", "source")
            commit = _git("-C", repo, "rev-parse", "HEAD")
            _, _, sources, inventory = load_git_sources(repo, commit)
            self.assertEqual(len(sources), 1)
            self.assertEqual(inventory["selected_source_files"], 1)


class AstGranularityTests(unittest.TestCase):
    def context(self):
        units = []
        for i in range(123):
            text = "int sample() { return 0; }\n"
            units.append(SourceUnit(
                path=f"src/{i:03d}.cpp", language="cpp", text=text,
                sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
                parse_status="complete" if i < 93 else "partial",
            ))
        units = tuple(units)
        req = ScanRequest(
            "ast-93-30", "fixture/m15-ast", "synthetic",
            snapshot_digest(units), "current-component:fixture/m15-ast"
        )
        return ScanContext(req, units, {"ast": {}})

    def test_93_complete_files_continue_and_30_are_unknown(self):
        class NeedsAst(MockCppDetector):
            required_facts = ("ast",)
        registry = DetectorRegistry()
        registry.register(NeedsAst())
        reports, sidecar = run_all_with_coverage(self.context(), registry)
        report, coverage = reports[0], sidecar["detectors"][NeedsAst.detector_id]
        self.assertEqual(report.status, "completed")
        self.assertEqual(report.scope_files, 93)
        self.assertEqual(len(report.parsing), 123)
        self.assertEqual(coverage["status"], "partial")
        self.assertEqual(len(coverage["analyzed_files"]), 93)
        self.assertEqual(len(coverage["unexamined"]), 30)
        self.assertTrue(all("incomplete_ast" in x["reason"] for x in coverage["unexamined"]))
        self.assertTrue(any("INCOMPLETE COVERAGE" in x for x in report.limitations))

    def test_whole_scope_mode_explicitly_blocks(self):
        class NeedsWhole(MockCppDetector):
            required_facts = ("ast",)
            ast_scope = "whole_scope"
        registry = DetectorRegistry()
        registry.register(NeedsWhole())
        reports, sidecar = run_all_with_coverage(self.context(), registry)
        self.assertEqual(reports[0].status, "blocked")
        self.assertEqual(reports[0].scope_files, 0)
        self.assertEqual(len(sidecar["detectors"][NeedsWhole.detector_id]["unexamined"]), 123)


class EvidenceContractTests(unittest.TestCase):
    def test_minimal_facts_never_fabricate_guards_or_targets(self):
        raw = {
            "src/a.cpp": {
                "parse_status": "complete",
                "functions": [
                    {"name": "f", "start_line": 1, "end_line": 3}
                ],
                "calls": [
                    {"name": "check(p)", "line": 2, "arguments": ["p"]}
                ],
                "variables": [],
            }
        }
        facts = build_syntax_facts(raw)["src/a.cpp"]
        self.assertEqual(facts["functions"][0]["name"], "f")
        self.assertEqual(facts["calls"][0]["resolved_target"], None)
        self.assertEqual(facts["guards"], [])
        self.assertIn("not resolved", facts["limitations"][0])

    def test_obligation_sidecar_does_not_rewrite_tooldiagnostic_v1(self):
        text = "int f() { return 0; }\n"
        unit = SourceUnit("src/test.cpp", "cpp", text,
                          hashlib.sha256(text.encode()).hexdigest())
        units = (unit,)
        req = ScanRequest("obligation", "fixture/m15-proof", "synthetic",
                          snapshot_digest(units), "current-component:fixture/m15-proof")
        context = ScanContext(req, units)

        class ObligationDetector(MockCppDetector):
            def detect(self, context, units):
                finding = DetectorFinding(
                    "src/test.cpp", 1, "candidate.rule", "Potential risk needs guard proof",
                    evidence_obligations=(
                        EvidenceObligation("guard_dominance", "prove guard covers dereference"),
                    ),
                )
                return DetectorRun(self.detector_id, self.version, "completed",
                                   analyzed_files=("src/test.cpp",), findings=(finding,))

        registry = DetectorRegistry()
        registry.register(ObligationDetector())
        reports, sidecar = run_all_with_coverage(context, registry)
        self.assertEqual(reports[0].diagnostic_count, 1)
        self.assertNotIn("evidence_obligations", reports[0].to_dict()["diagnostics"][0])
        obligations = sidecar["detectors"][ObligationDetector.detector_id]["evidence_obligations"]
        self.assertEqual(obligations[0]["obligations"][0]["status"], "unknown")
        self.assertEqual(obligations[0]["obligations"][0]["kind"], "guard_dominance")


if __name__ == "__main__":
    unittest.main()
