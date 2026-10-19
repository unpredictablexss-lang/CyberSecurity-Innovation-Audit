import hashlib
import json
import subprocess
import tempfile
import unittest
from dataclasses import asdict, replace
from pathlib import Path
from unittest.mock import patch

from src.benchmark.root_cause_matrix import ToolCandidate, build_revision_hit_matrix
from src.benchmark.source_mapping import map_snapshot_candidates
from src.benchmark.report_inputs import load_report_runs
from src.core.ast_scanner import scan_directory_ast
from src.core.report import render_markdown
from src.parser.ast import AstIndex, FunctionDef, parse_source
from src.report.benchmark_report import build_benchmark_report, render_markdown as render_summary
from test_benchmark_report_inputs import sample, normalized, diagnostic


class AstCoverageTests(unittest.TestCase):
    def test_records_error_and_missing_nodes_without_claiming_complete(self):
        for code in ("void broken( {", "void f() { int x = 1 }"):
            with self.subTest(code=code):
                index = parse_source(code, "cpp")
                self.assertEqual(index.parse_status, "partial")
                self.assertTrue(index.parse_issues)
                self.assertEqual(index.to_dict()["parse_status"], "partial")

    def test_qualified_method_name_is_not_scope_identifier(self):
        index = parse_source("void OHOS::Thing::run(int value) { memcpy(a,b,1); }", "cpp")
        self.assertEqual(index.parse_status, "complete")
        self.assertEqual(index.functions[0].name, "run")

    def test_scan_reports_partial_files_and_continues(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "good.c").write_text("void f() { memcpy(a,b,1); }", encoding="utf-8")
            (root / "bad.c").write_text("void broken( {", encoding="utf-8")
            result = scan_directory_ast(root)
            self.assertEqual(result.scanned_files, 2)
            self.assertEqual({item["status"] for item in result.to_dict()["parsing"]}, {"complete", "partial"})
            self.assertEqual(result.finding_count, 1)
            self.assertIn("AST parsing coverage", render_markdown(result))
            self.assertIn("partial", render_markdown(result))

    def test_parser_failure_is_recorded_and_other_files_continue(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.c").write_text("void f() {}", encoding="utf-8")
            (root / "b.c").write_text("void g() {}", encoding="utf-8")
            with patch("src.core.ast_scanner.parse_source", side_effect=[RuntimeError("parser failed"), AstIndex("c")]):
                result = scan_directory_ast(root)
            self.assertEqual([item["status"] for item in result.parsing], ["failed", "complete"])


class SnapshotMappingTests(unittest.TestCase):
    def test_static_replay_creates_reusable_revision_evidence(self):
        from scripts.replay_static_baselines import replay_baselines
        samples_dir = self.root / "samples"
        samples_dir.mkdir()
        (samples_dir / "seed.json").write_text(json.dumps(asdict(self.seed)), encoding="utf-8")
        output = self.root / "outputs"
        summary = replay_baselines(samples_dir, self.root / "unavailable", output,
                                   fallback_roots=[self.root])
        rows = summary.root_cause_matrix.rows
        self.assertEqual(len(rows), 16)
        self.assertEqual(sum(row.status == "miss" for row in rows), 4)
        self.assertEqual(sum(row.status == "unknown" for row in rows), 12)
        matrix = json.loads((output / "seed.fixed.matrix.json").read_text())
        self.assertEqual(matrix["commit"], self.fixed)
        self.assertEqual(matrix["scope_files"], 1)
        self.assertTrue((output / "inputs.json").exists())
        self.assertTrue((output / "summary.md").exists())
        self.assertEqual(self.git("rev-parse", "HEAD"), self.fixed)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "test")
        self.git("config", "user.email", "test@example.com")
        self.seed = replace(sample(), repository="owner/repo", repo_url="https://example.com/owner/repo")
        self.git("remote", "add", "origin", self.seed.repo_url)
        (self.repo / "src").mkdir()
        self.file = self.repo / "src" / "f.cpp"
        self.code = "void target() {\n  invoke();\n}\n"
        self.vulnerable = self.commit(self.code)
        self.fixed = self.commit("void unrelated() {\n  invoke();\n}\n")
        self.seed = replace(self.seed, vulnerable_commit=self.vulnerable, fixed_commit=self.fixed)
        self.candidates = [ToolCandidate("src/f.cpp", line=2)]

    def git(self, *args):
        process = subprocess.run(["git", "-C", str(self.repo), *args], capture_output=True, text=True)
        self.assertEqual(process.returncode, 0, process.stderr)
        return process.stdout.strip()

    def commit(self, code):
        self.file.write_text(code, encoding="utf-8")
        self.git("add", "src/f.cpp")
        self.git("commit", "-qm", "fixture")
        return self.git("rev-parse", "HEAD")

    def test_reads_pinned_blob_despite_different_head_and_dirty_file(self):
        self.file.write_text("void dirty() {}", encoding="utf-8")
        mapped, snapshots, incomplete = map_snapshot_candidates(self.repo, self.seed, self.vulnerable,
                                                                 ("src/f.cpp",), self.candidates)
        self.assertFalse(incomplete)
        self.assertEqual(mapped[0].symbol, "target")
        self.assertEqual(snapshots[0]["sha256"], hashlib.sha256(self.code.encode()).hexdigest())
        self.assertEqual(self.file.read_text(), "void dirty() {}")
        self.assertEqual(self.git("rev-parse", "HEAD"), self.fixed)

    def test_fixed_revision_maps_to_its_own_function(self):
        mapped, _, _ = map_snapshot_candidates(self.repo, self.seed, self.fixed, ("src/f.cpp",), self.candidates)
        self.assertEqual(mapped[0].symbol, "unrelated")

    def test_wrong_repository_and_missing_commit_rejected(self):
        with self.assertRaisesRegex(ValueError, "repository"):
            map_snapshot_candidates(self.repo, replace(self.seed, repository="other/repo"),
                                    self.vulnerable, ("src/f.cpp",), self.candidates)
        with self.assertRaisesRegex(ValueError, "pinned commit"):
            map_snapshot_candidates(self.repo, self.seed, "0" * 40, ("src/f.cpp",), self.candidates)

    def test_partial_empty_run_is_unknown_in_report_pipeline(self):
        broken = self.commit("void broken( {")
        seed = replace(self.seed, vulnerable_commit=broken)
        (self.root / "tool.json").write_text(json.dumps(normalized(seed)), encoding="utf-8")
        manifest = {"schema_version": 1, "runs": [{"sample_id": seed.sample_id, "revision": "vulnerable",
                    "report": "tool.json", "source_repo": "repo", "analyzed_files": ["src/f.cpp"]}]}
        path = self.root / "manifest.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        runs = load_report_runs(path, [seed])
        row = build_revision_hit_matrix([seed], runs).rows[0]
        self.assertEqual(row.status, "unknown")
        self.assertEqual(row.source_snapshots[0]["status"], "partial")
        self.assertIn("partial", row.reason)

    def test_normalized_symbol_mapping_reaches_matrix_and_keeps_snapshot_hash(self):
        (self.root / "tool.json").write_text(json.dumps(normalized(self.seed, diagnostics=[diagnostic(None)])), encoding="utf-8")
        path = self.root / "manifest.json"
        path.write_text(json.dumps({"schema_version": 1, "runs": [{"sample_id": self.seed.sample_id,
                        "revision": "vulnerable", "report": "tool.json", "source_repo": "repo",
                        "analyzed_files": ["src/f.cpp"]}]}), encoding="utf-8")
        runs = load_report_runs(path, [self.seed])
        row = build_revision_hit_matrix([self.seed], runs).rows[0]
        self.assertEqual(row.status, "possible_hit")
        self.assertEqual(row.source_snapshots[0]["commit"], self.vulnerable)
        summary = build_benchmark_report([self.seed], runs=runs)
        self.assertIn(row.source_snapshots[0]["sha256"], render_summary(summary))
        self.assertEqual(summary.to_dict()["root_cause_matrix"]["rows"][0]["source_snapshots"][0]["status"], "complete")

    def test_missing_line_or_overlapping_function_ranges_remain_unresolved(self):
        candidates = [ToolCandidate("src/f.cpp"), ToolCandidate("src/f.cpp", line=2)]
        index = AstIndex("cpp", functions=[FunctionDef("a", "void", [], 1, 3), FunctionDef("b", "void", [], 1, 3)])
        with patch("src.benchmark.source_mapping.parse_source", return_value=index):
            mapped, _, _ = map_snapshot_candidates(self.repo, self.seed, self.vulnerable, ("src/f.cpp",), candidates)
        self.assertTrue(all(item.symbol is None for item in mapped))

    def test_saved_ast_partial_or_absent_coverage_never_becomes_miss(self):
        for parsing in ([], [{"file": "src/f.cpp", "status": "partial"}],
                        [{"file": "src/f.cpp", "status": "complete"}]):
            with self.subTest(parsing=parsing):
                payload = normalized(self.seed, tool="own_ast")
                payload["parsing"] = parsing
                (self.root / "tool.json").write_text(json.dumps(payload), encoding="utf-8")
                path = self.root / "manifest.json"
                path.write_text(json.dumps({"schema_version": 1, "runs": [{"sample_id": self.seed.sample_id,
                                "revision": "vulnerable", "report": "tool.json", "analyzed_files": ["src/f.cpp"]}]}), encoding="utf-8")
                row = build_revision_hit_matrix([self.seed], load_report_runs(path, [self.seed])).rows[0]
                self.assertEqual(row.status, "miss" if parsing and parsing[0]["status"] == "complete" else "unknown")


if __name__ == "__main__":
    unittest.main()
