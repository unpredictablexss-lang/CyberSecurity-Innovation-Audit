from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from src.ohscanner.indexing import prepare_git_context
from src.ohscanner.contracts import ScanContext, ScanRequest
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.git_source import resolve_commit
from src.ohscanner.detectors.catalog import build_registry
from src.workbench.service import detector_metadata
from src.workbench.sources import manifest_from_context
from src.workbench.planning import plan_audit, metadata_from_detectors


class SourcePlanningManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.repo = Path(cls.temp.name)
        cls.git("init", "-q")
        cls.git("config", "user.name", "Planning Test")
        cls.git("config", "user.email", "planning@example.invalid")
        (cls.repo / "a.cpp").write_text("int main() { return 0; }\n")
        (cls.repo / "b.c").write_text("int value(void) { return 1; }\n")
        (cls.repo / "c.js").write_text("const value = 1;\n")
        (cls.repo / "unknown.rs").write_text("fn main() {}\n")
        (cls.repo / "README.md").write_text("not source\n")
        (cls.repo / "invalid.cpp").write_bytes(b"\xff\xfe")
        (cls.repo / "big.cpp").write_bytes(b"a" * (1024 * 1024 + 1))
        (cls.repo / "linked.cpp").symlink_to("a.cpp")
        cls.git("add", ".")
        cls.git("commit", "-qm", "fixed source")
        cls.commit = cls.git("rev-parse", "HEAD").strip()
        cls.context, cls.tree, cls.inventory, _, cls.sources = prepare_git_context(cls.repo, "test/planning", cls.commit)

    @classmethod
    def git(cls, *args):
        return subprocess.check_output(["git", "-C", str(cls.repo), *args], text=True)

    def test_real_fixed_context_preserves_identity_inventory_and_actual_metadata(self):
        source = manifest_from_context(self.context, self.tree, self.inventory, self.sources)
        self.assertEqual(source.commit, self.commit)
        self.assertEqual(source.snapshot_sha256, self.context.request.snapshot_sha256)
        self.assertEqual(source.unclassified_entries, 2)  # Rust is not core-supported.
        self.assertEqual(source.skipped_entries, 3)  # symlink, oversized, non-UTF8.
        self.assertTrue(all(f.blob_oid for f in source.files))
        rows = detector_metadata()
        approved = build_registry(tuple(row["id"] for row in rows))
        enriched = metadata_from_detectors(rows, approved.detectors())
        plan = plan_audit(source, enriched)
        self.assertEqual(set(plan["suggested_detector_ids"]), {row["id"] for row in rows if row.get("default_enabled", True)})
        self.assertEqual(plan["status"], "ready_with_limitations")
        self.assertEqual(plan["files_without_planned_detector"], [])
        script = next(d for d in plan["detectors"] if d["id"] == "ohscanner.oh.arkts_js")
        self.assertEqual(script["matched_files"], ["c.js"])
        self.assertTrue(all("c.js" not in d["matched_files"] for d in plan["detectors"]
                            if d["id"] != "ohscanner.oh.arkts_js"))
        self.assertTrue(all(d["execution_status"] == "not_run" for d in plan["detectors"]))

    def test_dirty_worktree_does_not_change_pinned_source_plan(self):
        original = (self.repo / "a.cpp").read_bytes()
        try:
            (self.repo / "a.cpp").write_text("dirty local replacement")
            before = self.git("status", "--porcelain")
            context, tree, inventory, _, sources = prepare_git_context(self.repo, "test/planning", self.commit)
            adapted = manifest_from_context(context, tree, inventory, sources)
            self.assertEqual(adapted.snapshot_sha256, self.context.request.snapshot_sha256)
            self.assertEqual((self.repo / "a.cpp").read_text(), "dirty local replacement")
            self.assertEqual(self.git("status", "--porcelain"), before)
        finally:
            (self.repo / "a.cpp").write_bytes(original)

    def test_source_loading_reuses_offline_git_and_adapter_does_no_io(self):
        run = subprocess.run
        with patch("src.ohscanner.git_source.subprocess.run", wraps=run) as calls:
            context, tree, inventory, _, sources = prepare_git_context(self.repo, "test/planning", self.commit)
        for call in calls.call_args_list:
            self.assertEqual(call.kwargs["env"]["GIT_ALLOW_PROTOCOL"], "")
            self.assertEqual(call.kwargs["env"]["GIT_NO_LAZY_FETCH"], "1")
            self.assertNotIn("fetch", call.args[0])
        with patch("subprocess.run", side_effect=AssertionError("adapter ran Git")):
            manifest_from_context(context, tree, inventory, sources)

    def test_tree_counts_snapshot_and_content_mismatch_rejected(self):
        for key, value in [("git_tree", "c" * 40), ("tracked_entries", 999), ("selected_source_files", 999), ("selected_source_bytes", 1), ("non_source", True)]:
            inventory = {**self.inventory, key: value}
            with self.subTest(key=key), self.assertRaises(ValueError):
                manifest_from_context(self.context, self.tree, inventory, self.sources)
        context = replace(self.context, request=replace(self.context.request, snapshot_sha256="e" * 64))
        with self.assertRaises(ValueError):manifest_from_context(context, self.tree, self.inventory)
        sources = (replace(self.sources[0], data=b"tampered"), *self.sources[1:])
        with self.assertRaises(ValueError):manifest_from_context(self.context, self.tree, self.inventory, sources)
        sources = (replace(self.sources[0], oid="e" * 40), *self.sources[1:])
        with self.assertRaises(ValueError):manifest_from_context(self.context, self.tree, self.inventory, sources)

    def test_optional_blob_ids_remain_missing_not_fabricated(self):
        source = manifest_from_context(self.context, self.tree, self.inventory)
        self.assertTrue(all(f.blob_oid is None for f in source.files))

    def test_fixture_provenance_rejected_and_inputs_not_mutated(self):
        inventory = deepcopy(self.inventory)
        context = replace(self.context, request=replace(self.context.request, provenance="fixture"))
        with self.assertRaises(ValueError):manifest_from_context(context, self.tree, inventory)
        manifest_from_context(self.context, self.tree, inventory, self.sources)
        self.assertEqual(inventory, self.inventory)

    def test_known_skipped_file_reasons_are_preserved_not_only_counted(self):
        source = manifest_from_context(self.context, self.tree, self.inventory, self.sources)
        self.assertEqual(source.to_dict()["skipped_files"], [
            {"file": "big.cpp", "reason": "oversize"},
            {"file": "invalid.cpp", "reason": "non_utf8"},
        ])
        self.assertEqual(source.skipped_entries, 3)  # symlink remains an aggregate gap.

    def test_forged_skipped_paths_and_counts_are_rejected(self):
        inventory = deepcopy(self.inventory)
        inventory["skipped"] = []
        with self.assertRaises(ValueError):manifest_from_context(self.context, self.tree, inventory)
        for path in ["../outside.cpp", "a.cpp"]:
            inventory = deepcopy(self.inventory)
            inventory["skipped"][0]["file"] = path
            with self.subTest(path=path), self.assertRaises(ValueError):
                manifest_from_context(self.context, self.tree, inventory)

    def test_real_empty_commit_inventory_produces_empty_scope_not_safe(self):
        # The planner consumes inventory. The current prepare_git_context reader
        # rejects no-source repositories, so do not pretend that reader changed.
        with tempfile.TemporaryDirectory() as name:
            repo = Path(name)
            def git(*args):
                return subprocess.check_output(["git", "-C", str(repo), *args], text=True)
            git("init", "-q")
            git("-c", "user.name=Empty Test", "-c", "user.email=empty@example.invalid",
                "commit", "--allow-empty", "-qm", "empty tree")
            commit, tree = resolve_commit(repo, git("rev-parse", "HEAD").strip())
            request = ScanRequest("empty-index", "test/empty", commit,
                                  snapshot_digest(()), "current-component:test/empty",
                                  profile_id="light-ast", provenance="git_object")
            inventory = {key: 0 for key in ("tracked_entries", "out_of_scope", "non_source",
                         "symlinks", "submodules", "oversize", "binary_or_non_utf8",
                         "selected_source_files", "selected_source_bytes")}
            inventory.update(git_tree=tree, declared_scope=["."], skipped=[])
            source = manifest_from_context(ScanContext(request, ()), tree, inventory, ())
            plan = plan_audit(source, detector_metadata())
            self.assertEqual(plan["status"], "empty_scope")
            self.assertEqual(plan["suggested_detector_ids"], [])
            self.assertEqual(plan["security_assessment"], "unknown")
