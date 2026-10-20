import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts.check_change_scope import check


class ChangeScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.git("init", "-q")
        self.git("config", "user.email", "scope@example.invalid")
        self.git("config", "user.name", "Scope Test")
        self.write("config/collaboration/ownership.json", json.dumps({
            "lanes": {"cpp": {"allowed": ["detectors/cpp/**"]}},
            "shared_owner_only": ["config/**", "core/**"],
        }))
        self.write("detectors/cpp/old.py", "old")
        self.write("core/runner.py", "core")
        self.git("add", ".")
        self.git("commit", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD").strip()

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args], text=True)

    def write(self, name, content):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def test_own_committed_staged_unstaged_untracked_changes_are_allowed(self):
        self.write("detectors/cpp/old.py", "committed")
        self.git("commit", "-qam", "own change")
        self.write("detectors/cpp/staged.py", "staged")
        self.git("add", "detectors/cpp/staged.py")
        self.write("detectors/cpp/old.py", "unstaged")
        self.write("detectors/cpp/new.py", "untracked")
        result = check(self.repo, self.base, "cpp")
        self.assertEqual(result["violations"], [])
        self.assertEqual(len(result["checked_paths"]), 3)

    def test_move_out_of_shared_directory_checks_deleted_source(self):
        self.git("mv", "core/runner.py", "detectors/cpp/moved.py")
        result = check(self.repo, self.base, "cpp")
        self.assertIn("core/runner.py", result["violations"])
        self.assertIn("detectors/cpp/moved.py", result["checked_paths"])

    def test_modified_policy_cannot_authorize_shared_changes(self):
        self.write("config/collaboration/ownership.json", json.dumps({
            "lanes": {"cpp": {"allowed": ["**"]}}, "shared_owner_only": [],
        }))
        self.write("core/runner.py", "changed")
        self.git("add", ".")
        self.git("commit", "-qm", "try to relax policy")
        self.assertEqual(check(self.repo, self.base, "cpp")["violations"],
                         ["config/collaboration/ownership.json", "core/runner.py"])

    def test_unknown_lane_and_abbreviated_base_fail_closed(self):
        with self.assertRaises(ValueError):
            check(self.repo, self.base, "other")
        with self.assertRaises(ValueError):
            check(self.repo, self.base[:8], "cpp")

    def test_baseline_must_be_ancestor(self):
        self.git("checkout", "--orphan", "unrelated")
        self.git("commit", "-qm", "unrelated root")
        with self.assertRaises(subprocess.CalledProcessError):
            check(self.repo, self.base, "cpp")
