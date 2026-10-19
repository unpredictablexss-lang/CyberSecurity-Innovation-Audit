from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "research/data_sensitive"))
from d13_verify_git_objects import VerificationError, git_blob_sha, verify_manifest


def run_git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def manifest_row(commit: str, tree: str, path: str, data: bytes) -> dict:
    return {
        "commit": commit,
        "tree": tree,
        "file": path,
        "blob": git_blob_sha(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }


class SourceGitObjectVerificationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name) / "repo"
        self.repo.mkdir()
        run_git(self.repo, "init", "-q")
        run_git(self.repo, "config", "user.email", "test@example.invalid")
        run_git(self.repo, "config", "user.name", "Test")
        run_git(self.repo, "config", "commit.gpgsign", "false")
        self.path = "sample.cpp"
        self.before = b"int f() { return 1; }\n"
        (self.repo / self.path).write_bytes(self.before)
        run_git(self.repo, "add", self.path)
        run_git(self.repo, "commit", "-q", "-m", "before")
        self.before_commit = run_git(self.repo, "rev-parse", "HEAD")
        self.before_tree = run_git(self.repo, "rev-parse", "HEAD^{tree}")
        self.after = b"int f() { return 0; }\n"
        (self.repo / self.path).write_bytes(self.after)
        run_git(self.repo, "add", self.path)
        run_git(self.repo, "commit", "-q", "-m", "after")
        self.after_commit = run_git(self.repo, "rev-parse", "HEAD")
        self.after_tree = run_git(self.repo, "rev-parse", "HEAD^{tree}")
        self.manifest = {
            "repository": "example/repo",
            "before_commit": self.before_commit,
            "after_commit": self.after_commit,
            "before_tree": self.before_tree,
            "after_tree": self.after_tree,
            "files": [
                manifest_row(self.before_commit, self.before_tree, self.path, self.before),
                manifest_row(self.after_commit, self.after_tree, self.path, self.after),
            ],
        }

    def tearDown(self):
        self.tmp.cleanup()

    def test_manifest_files_match_local_commit_objects_offline(self):
        result = verify_manifest(self.repo, self.manifest)
        self.assertEqual(result["files_verified"], 2)
        self.assertEqual(result["verified_file_counts"], {
            self.before_commit: 1,
            self.after_commit: 1,
        })
        self.assertEqual(run_git(self.repo, "rev-parse", "--is-shallow-repository"), "false")

    def test_manifest_digest_mismatch_is_rejected(self):
        damaged = json.loads(json.dumps(self.manifest))
        damaged["files"][1]["sha256"] = "0" * 64
        with self.assertRaises(VerificationError):
            verify_manifest(self.repo, damaged)


if __name__ == "__main__":
    unittest.main()
