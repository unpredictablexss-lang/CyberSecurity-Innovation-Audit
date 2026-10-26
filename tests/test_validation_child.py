import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from src.workbench.validation_child import patched_target
from src.ohscanner.poc.runner import run_poc


def run(repo: Path, *args: str, input_data: bytes | None = None) -> bytes:
    done = subprocess.run(
        ["git", "-C", str(repo), *args],
        input=input_data,
        capture_output=True,
        check=True,
    )
    return done.stdout


def commit_file(repo: Path, name: str, content: str, message: str) -> str:
    (repo / name).write_text(content, encoding="utf-8")
    run(repo, "add", "--", name)
    run(repo, "commit", "-qm", message)
    return run(repo, "rev-parse", "HEAD").decode().strip()


class PatchedTargetTests(unittest.TestCase):
    def test_run_poc_accepts_a_manifest_copied_out_of_the_harness_directory(self) -> None:
        self.assertIn("harness_dir", run_poc.__code__.co_varnames)

    def test_patch_replay_fetches_disconnected_shallow_revisions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            origin = root / "origin"
            source = root / "source"
            work = root / "work"
            origin.mkdir()
            run(origin, "init", "-q")
            run(origin, "config", "user.name", "Test")
            run(origin, "config", "user.email", "test@example.invalid")

            vulnerable = commit_file(origin, "target.cpp", "int f() { return 1; }\n", "vulnerable")
            run(origin, "checkout", "-qb", "fixed")
            fixed = commit_file(origin, "target.cpp", "int f() { return 2; }\n", "fixed")
            run(origin, "checkout", "-q", "--detach", vulnerable)

            source.mkdir()
            run(source, "init", "-q")
            run(source, "remote", "add", "origin", str(origin))
            run(source, "fetch", "-q", "--depth", "1", "origin", vulnerable)
            run(source, "fetch", "-q", "--depth", "1", "origin", fixed)
            run(source, "checkout", "-q", "--detach", vulnerable)

            manifest = {
                "revisions": {
                    "vulnerable": {"commit": vulnerable, "expected": "trigger"},
                    "fixed": {"commit": fixed, "expected": "no_trigger"},
                },
                "sources": [
                    {
                        "revision": "vulnerable",
                        "commit": vulnerable,
                        "path": "target.cpp",
                        "sha256": hashlib.sha256(b"int f() { return 1; }\n").hexdigest(),
                    },
                    {
                        "revision": "fixed",
                        "commit": fixed,
                        "path": "target.cpp",
                        "sha256": hashlib.sha256(b"int f() { return 2; }\n").hexdigest(),
                    }
                ],
                "cases": [],
            }

            clone, synthetic, patch_hash = patched_target(source, work, manifest)

            run(clone, "cat-file", "-e", fixed + "^{commit}")
            self.assertEqual((clone / "target.cpp").read_text(), "int f() { return 2; }\n")
            self.assertEqual(len(patch_hash), 64)
            self.assertNotEqual(synthetic, vulnerable)
            self.assertNotEqual(synthetic, fixed)
            self.assertEqual(manifest["revisions"]["patched"]["origin_commit"], vulnerable)
            self.assertEqual(manifest["revisions"]["patched"]["fix_commit"], fixed)


if __name__ == "__main__":
    unittest.main()
