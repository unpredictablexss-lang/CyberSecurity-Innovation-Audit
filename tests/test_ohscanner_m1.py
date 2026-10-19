"""M1: offline Git object index, AST coverage and source identity regression tests."""

import json
import io
import tarfile
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from src.ohscanner.contracts import ScanRequest
from src.ohscanner.frontend import index_sources
from src.ohscanner.git_source import load_git_sources
from src.ohscanner.indexing import prepare_git_context, run_git_index
from src.ohscanner.planning import plan_context
from src.ohscanner.mocks import MockCppDetector
from src.ohscanner.runner import DetectorRegistry, run_all, run_all_with_coverage

PROJECT = Path(__file__).resolve().parents[1]


def git(directory, *args):
    done = subprocess.run(["git", "-C", str(directory), *args],
                          capture_output=True, text=True, check=True, timeout=20)
    return done.stdout.strip()


class GitObjectIndexTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "sample-repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q")
        git(self.repo, "config", "user.email", "ci@example.invalid")
        git(self.repo, "config", "user.name", "CI")
        (self.repo / "src").mkdir()
        (self.repo / "src" / "a.cpp").write_text(
            "int value(int a) { return a + 1; }\n", encoding="utf-8"
        )
        (self.repo / "src" / "bridge.ets").write_text(
            "function bridge(): number { return 1; }\n", encoding="utf-8"
        )
        (self.repo / "README.md").write_text("not a source\n", encoding="utf-8")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "fixed M1 fixture")
        self.commit = git(self.repo, "rev-parse", "HEAD")

    def test_index_real_commit_objects_and_language_parse_state(self):
        context, tree, inventory, coverage, sources = prepare_git_context(
            self.repo, "fixture/m1-sample", self.commit
        )
        self.assertEqual(context.request.commit, self.commit)
        self.assertEqual(context.request.provenance, "git_object")
        self.assertEqual(len(tree), 40)
        self.assertEqual(inventory["tracked_entries"], 3)
        self.assertEqual(inventory["non_source"], 1)
        self.assertEqual(coverage["languages"], {"arkts": 1, "cpp": 1})
        indexed = {unit.path: unit for unit in context.units}
        self.assertEqual(indexed["src/a.cpp"].parse_status, "complete")
        self.assertEqual(indexed["src/bridge.ets"].parse_status, "complete")
        self.assertGreaterEqual(len(context.shared_facts["ast"]["src/a.cpp"]["functions"]), 1)
        self.assertNotIn("src/bridge.ets", context.shared_facts["ast"])
        self.assertEqual([s.path for s in sources], sorted(s.path for s in sources))

    def test_git_blobs_are_read_in_one_bounded_batch(self):
        original_run = subprocess.run
        commands = []

        def record_run(*args, **kwargs):
            commands.append(args[0])
            return original_run(*args, **kwargs)

        with patch("src.ohscanner.git_source.subprocess.run", side_effect=record_run):
            _, _, sources, inventory = load_git_sources(self.repo, self.commit)

        cat_file_calls = [command for command in commands
                          if command[-2:] == ["cat-file", "--batch"]]
        self.assertEqual(len(cat_file_calls), 1)
        self.assertFalse(any(command[-2:-1] == ["blob"] for command in commands))
        by_path = {source.path: source.data for source in sources}
        self.assertEqual(by_path["src/a.cpp"],
                         (self.repo / "src" / "a.cpp").read_bytes())
        self.assertEqual(by_path["src/bridge.ets"],
                         (self.repo / "src" / "bridge.ets").read_bytes())
        self.assertEqual(inventory["selected_source_files"], 2)

    def test_git_blob_batches_are_capped_at_512_files(self):
        for index in range(511):
            (self.repo / "src" / f"batch_{index:03d}.c").write_text(
                "int sample(void) { return 0; }\n", encoding="utf-8"
            )
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "more source files")
        commit = git(self.repo, "rev-parse", "HEAD")
        original_run = subprocess.run
        commands = []

        def record_run(*args, **kwargs):
            commands.append(args[0])
            return original_run(*args, **kwargs)

        with patch("src.ohscanner.git_source.subprocess.run", side_effect=record_run):
            _, _, sources, inventory = load_git_sources(self.repo, commit)

        cat_file_calls = [command for command in commands
                          if command[-2:] == ["cat-file", "--batch"]]
        self.assertEqual(len(cat_file_calls), 2)
        self.assertEqual(len(sources), 513)
        self.assertEqual(inventory["selected_source_files"], 513)

    def test_pinned_commit_ignores_worktree_and_new_head(self):
        first = prepare_git_context(self.repo, "fixture/m1-sample", self.commit)
        (self.repo / "src" / "a.cpp").write_text("int later = 42;\n", encoding="utf-8")
        self.assertEqual(first[0].units, prepare_git_context(
            self.repo, "fixture/m1-sample", self.commit)[0].units)
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "after")
        self.assertEqual(first[0].units, prepare_git_context(
            self.repo, "fixture/m1-sample", self.commit)[0].units)
        later = git(self.repo, "rev-parse", "HEAD")
        self.assertNotEqual(self.commit, later)
        self.assertNotEqual(first[0].request.snapshot_sha256, prepare_git_context(
            self.repo, "fixture/m1-sample", later)[0].request.snapshot_sha256)

    def test_sha_and_reference_constraints(self):
        for invalid in ("HEAD", "main", "a" * 39, "g" * 40, "A" * 40):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                load_git_sources(self.repo, invalid)
        with self.assertRaises(ValueError):
            ScanRequest("x", "fixture/m1-sample", "notsha", "f" * 64,
                        "current-component:fixture/m1-sample",
                        profile_id="light-ast", provenance="git_object")

    def test_invalid_scopes_rejected(self):
        for scope in (("../outside",), ("/absolute",), ("src/../bad",), (), ("src", "src")):
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                load_git_sources(self.repo, self.commit, scope)

    def test_scope_is_segment_aware(self):
        (self.repo / "src-extra").mkdir()
        (self.repo / "src-extra" / "outside.cpp").write_text("int x;\n", encoding="utf-8")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "extra")
        updated = git(self.repo, "rev-parse", "HEAD")
        _, _, sources, inventory = load_git_sources(self.repo, updated, ("src",))
        self.assertEqual(len(sources), 2)
        self.assertGreaterEqual(inventory["out_of_scope"], 2)

    def test_empty_source_scope_is_error(self):
        with self.assertRaisesRegex(ValueError, "no supported UTF-8"):
            load_git_sources(self.repo, self.commit, ("README.md",))

    def test_symlink_not_followed_and_non_utf8_not_disguised(self):
        (self.repo / "src" / "link.cpp").symlink_to(self.repo / "src" / "a.cpp")
        (self.repo / "src" / "broken.cpp").write_bytes(b"\xff\xfe\x00")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "unsafe entries")
        updated = git(self.repo, "rev-parse", "HEAD")
        _, _, sources, inventory = load_git_sources(self.repo, updated)
        self.assertEqual(inventory["symlinks"], 1)
        self.assertEqual(inventory["binary_or_non_utf8"], 1)
        self.assertEqual(len(sources), 2)
        self.assertEqual(inventory["skipped"][0]["reason"], "non_utf8")

    def test_oversize_file_explicitly_skipped(self):
        (self.repo / "src" / "huge.cpp").write_bytes(b"x" * (1024 * 1024 + 1))
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "huge")
        updated = git(self.repo, "rev-parse", "HEAD")
        _, _, sources, inventory = load_git_sources(self.repo, updated)
        self.assertEqual(inventory["oversize"], 1)
        self.assertEqual(len(sources), 2)

    def test_index_reports_no_detectors_and_same_commit(self):
        out_json = self.root / "index.json"
        out_md = self.root / "index.md"
        report = run_git_index(self.repo, "fixture/m1-sample", self.commit,
                               (".",), out_json, out_md)
        self.assertEqual(report["detector_runs"], [])
        self.assertEqual(report["candidate_count"], 0)
        self.assertEqual(report["validated_vulnerability"], 0)
        self.assertEqual(report["provenance"], "local_git_objects")
        self.assertEqual(report["commit"], self.commit)
        self.assertEqual(report["scope"]["selected_source_files"], 2)
        self.assertTrue(out_md.read_text(encoding="utf-8").startswith("# OHScanner M1"))
        self.assertEqual(json.loads(out_json.read_text())["git_tree"], report["git_tree"])

    def test_cli_end_to_end_fixed_commit_index(self):
        output = self.root / "out"
        proc = subprocess.run(
            [sys.executable, "-m", "src.cli", "ohscan-index",
             "--repo-dir", str(self.repo), "--repository", "fixture/m1-sample",
             "--commit", self.commit, "--json-out", str(output / "r.json"),
             "--md-out", str(output / "r.md")],
            cwd=PROJECT, capture_output=True, text=True, timeout=40, check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("no vulnerability detection", proc.stdout)
        self.assertEqual(json.loads((output / "r.json").read_text())["commit"], self.commit)

    def test_cli_rejects_moving_branch_name(self):
        proc = subprocess.run(
            [sys.executable, "-m", "src.cli", "ohscan-index",
             "--repo-dir", str(self.repo), "--repository", "fixture/m1-sample",
             "--commit", "HEAD"],
            cwd=PROJECT, capture_output=True, text=True, timeout=40, check=False,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("full lowercase Git commit SHA", proc.stderr)

    def test_pinned_context_can_use_shared_bridge_without_external_tools(self):
        context, tree, inventory, coverage, sources = prepare_git_context(
            self.repo, "fixture/m1-sample", self.commit
        )
        registry = DetectorRegistry()
        registry.register(MockCppDetector())
        runs = run_all(context, registry)
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0].status, "completed")
        self.assertEqual(runs[0].commit, self.commit)
        self.assertEqual(runs[0].scope_files, 1)
        self.assertTrue(any("local Git objects pinned" in x for x in runs[0].limitations))
        self.assertFalse(any("synthetic fixture only" in x for x in runs[0].limitations))
        self.assertEqual(runs[0].diagnostic_count, 0)

    def test_ast_requirement_runs_complete_files_and_preserves_partial_coverage(self):
        (self.repo / "src" / "broken.cpp").write_text(
            "int broken( {\n", encoding="utf-8"
        )
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "syntactically partial")
        updated = git(self.repo, "rev-parse", "HEAD")
        context, _, _, _, _ = prepare_git_context(
            self.repo, "fixture/m1-sample", updated
        )
        class NeedsAst(MockCppDetector):
            required_facts = ("ast",)
        registry = DetectorRegistry()
        registry.register(NeedsAst())
        results, coverage = run_all_with_coverage(context, registry)
        result = results[0]
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.scope_files, 1)
        self.assertEqual(len(result.parsing), 2)
        self.assertTrue(any("INCOMPLETE COVERAGE" in x for x in result.limitations))
        details = coverage["detectors"][NeedsAst.detector_id]
        self.assertEqual(details["status"], "partial")
        self.assertEqual(details["analyzed_files"], ["src/a.cpp"])
        self.assertEqual(details["unexamined"][0]["file"], "src/broken.cpp")
        self.assertIn("incomplete_ast", details["unexamined"][0]["reason"])

    def test_whole_scope_ast_can_still_block_on_one_partial_file(self):
        (self.repo / "src" / "broken.cpp").write_text("int broken( {\n", encoding="utf-8")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "partial")
        updated = git(self.repo, "rev-parse", "HEAD")
        context, _, _, _, _ = prepare_git_context(self.repo, "fixture/m1-sample", updated)
        class NeedsWholeAst(MockCppDetector):
            required_facts = ("ast",)
            ast_scope = "whole_scope"
        registry = DetectorRegistry()
        registry.register(NeedsWholeAst())
        result, coverage = run_all_with_coverage(context, registry)
        self.assertEqual(result[0].status, "blocked")
        self.assertEqual(result[0].scope_files, 0)
        self.assertEqual(coverage["detectors"][NeedsWholeAst.detector_id]["status"], "blocked")
        self.assertEqual(len(coverage["detectors"][NeedsWholeAst.detector_id]["unexamined"]), 2)

    def test_missing_c_cpp_grammar_is_not_silently_complete(self):
        from src.ohscanner.git_source import GitSource
        text = "int incomplete( {\n"
        units, ast, coverage = index_sources(
            (GitSource("bad.cpp", "cpp", "0" * 40, text.encode()),)
        )
        self.assertIn(units[0].parse_status, ("partial", "failed"))
        self.assertNotEqual(coverage["parsing_status"], {"complete": 1})

    def test_tracked_tar_gz_members_are_indexed_and_bound_to_archive(self):
        payload = b"int png_decode(void) { png_read_end(png_ptr, info_ptr); return 0; }\n"
        archive_path = self.repo / "vendor" / "libpng.tar.gz"
        archive_path.parent.mkdir()
        with tarfile.open(archive_path, "w:gz") as tar:
            info = tarfile.TarInfo("libpng/png.c")
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
            readme = b"release notes\n"
            info = tarfile.TarInfo("libpng/README.md")
            info.size = len(readme)
            tar.addfile(info, io.BytesIO(readme))
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "add source archive")
        commit = git(self.repo, "rev-parse", "HEAD")
        context, tree, inventory, _, sources = prepare_git_context(
            self.repo, "fixture/archive-sample", commit, ("vendor/libpng.tar.gz",)
        )
        source = next(item for item in sources if item.archive_binding)
        self.assertEqual(source.path, "vendor/libpng.tar.gz.members/libpng/png.c")
        self.assertEqual(source.data, payload)
        self.assertEqual(source.archive_binding["archive_path"], "vendor/libpng.tar.gz")
        self.assertEqual(source.archive_binding["member_path"], "libpng/png.c")
        self.assertEqual(source.archive_binding["member_sha256"], context.units[0].sha256)
        self.assertEqual(inventory["source_archives"][0]["selected_sources"], 1)
        manifest = __import__("src.workbench.sources", fromlist=["manifest_from_context"]).manifest_from_context(
            context, tree, inventory, sources
        )
        self.assertIsNone(manifest.files[0].blob_oid)
        self.assertEqual(manifest.files[0].archive_binding["archive_path"], "vendor/libpng.tar.gz")

    def test_invalid_tracked_archive_is_partial_not_a_false_clean_result(self):
        from src.ohscanner.git_source import _archive_member_sources
        selected, inventory = _archive_member_sources("bad.tar.gz", "b" * 40, b"not a gzip tar")
        self.assertEqual(selected, ())
        self.assertEqual(inventory["status"], "partial")
        self.assertTrue(inventory["limitations"])

    def test_archive_member_limits_are_fail_closed(self):
        from src.ohscanner.git_source import _archive_member_sources
        payload = b"x" * (1024 * 1024 + 1)
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
            info = tarfile.TarInfo("large.c")
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
        selected, inventory = _archive_member_sources("large.tar.gz", "a" * 40, buffer.getvalue())
        self.assertEqual(selected, ())
        self.assertEqual(inventory["oversize"], 1)
        self.assertEqual(inventory["skipped"][0]["reason"], "oversize")


if __name__ == "__main__":
    unittest.main()
