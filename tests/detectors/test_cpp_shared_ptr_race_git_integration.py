from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from src.ohscanner.detectors.cpp.shared_ptr_race_detector import (
    SharedPtrRaceDetector,
)
from src.ohscanner.indexing import prepare_git_context
from src.ohscanner.runner import DetectorRegistry, run_all
from tests.detectors.shared_ptr_race_fixture_support import (
    load_shared_ptr_race_units,
    unit_by_path,
)


def _git(directory: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(directory), *args],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    ).stdout.strip()


class SharedPtrRaceGitIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "pinned-repo"
        self.repo.mkdir()
        _git(self.repo, "init", "-q")
        _git(self.repo, "config", "user.email", "ci@example.invalid")
        _git(self.repo, "config", "user.name", "CI")
        (self.repo / "base" / "include").mkdir(parents=True)
        units = load_shared_ptr_race_units()
        self.vulnerable_text = unit_by_path(
            units, "vulnerable_non_atomic_shared_ptr.cpp"
        ).text
        self.fixed_text = unit_by_path(
            units, "fixed_atomic_shared_ptr.cpp"
        ).text

    def _write_source(self, text: str) -> None:
        (self.repo / "base" / "include" / "singleton.h").write_text(
            text, encoding="utf-8"
        )

    def _commit(self, message: str) -> str:
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-qm", message)
        return _git(self.repo, "rev-parse", "HEAD")

    def _run(self, commit: str):
        context, _tree, _inventory, _coverage, _sources = prepare_git_context(
            self.repo,
            "synthetic/fixture",
            commit,
            includes=("base/include/singleton.h",),
        )
        registry = DetectorRegistry()
        registry.register(SharedPtrRaceDetector())
        result = run_all(context, registry)[0]
        return context, result

    def test_pinned_git_context_runs_vulnerable_and_fixed_separately(self) -> None:
        self._write_source(self.vulnerable_text)
        vulnerable_commit = self._commit("vulnerable shape")
        vulnerable_context, vulnerable_result = self._run(vulnerable_commit)
        self.assertEqual(vulnerable_context.request.provenance, "git_object")
        self.assertEqual(vulnerable_context.request.commit, vulnerable_commit)
        self.assertEqual(vulnerable_result.status, "completed")
        self.assertEqual(vulnerable_result.tool, "ohscanner.cpp.shared_ptr_race")
        self.assertEqual(vulnerable_result.tool_version, "0.1.0-proposed")
        self.assertGreater(vulnerable_result.diagnostic_count, 0)
        self.assertTrue(
            all(item.evidence_type == "syntax" for item in vulnerable_result.diagnostics)
        )
        self.assertTrue(
            all(item.severity == "unassessed" for item in vulnerable_result.diagnostics)
        )
        self.assertTrue(
            all(item.confidence == "unassessed" for item in vulnerable_result.diagnostics)
        )

        self._write_source(self.fixed_text)
        fixed_commit = self._commit("fixed shape")
        fixed_context, fixed_result = self._run(fixed_commit)
        self.assertEqual(fixed_context.request.commit, fixed_commit)
        self.assertEqual(fixed_result.status, "completed")
        self.assertEqual(fixed_result.diagnostic_count, 0)
        self.assertNotEqual(
            vulnerable_context.request.snapshot_sha256,
            fixed_context.request.snapshot_sha256,
        )

    def test_pinned_run_ignores_uncommitted_worktree_drift(self) -> None:
        self._write_source(self.vulnerable_text)
        commit = self._commit("vulnerable shape")
        _context, before = self._run(commit)

        # Mutate only the worktree, not the pinned Git object.
        self._write_source(self.fixed_text)
        _context_after, after = self._run(commit)
        for field in ("run_id", "tool", "tool_version", "target_id", "commit",
                      "scope_files", "scope_loc", "status", "diagnostics"):
            self.assertEqual(getattr(before, field), getattr(after, field))


if __name__ == "__main__":
    unittest.main()
