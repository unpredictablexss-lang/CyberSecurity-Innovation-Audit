"""Workbench detector shard checkpoint integrity and invalidation controls."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from src.ohscanner.execution import run_fixed_commit_scan


ROOT = Path(__file__).resolve().parents[1]
DETECTOR = "ohscanner.example.cpp.copy-calls"
ENGINE = "a" * 64


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True,
                          text=True, capture_output=True, timeout=20).stdout.strip()


class DetectorCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q")
        git(self.repo, "config", "user.email", "checkpoint@example.invalid")
        git(self.repo, "config", "user.name", "Checkpoint test")
        (self.repo / "src").mkdir()
        (self.repo / "src/copy.cpp").write_text(
            "void f(char* dst, char* src) { memcpy(dst, src, 10); }\n", encoding="utf-8")
        (self.repo / "src/partial.cpp").write_text(
            "int malformed( { memcpy(dst, src, 10);\n", encoding="utf-8")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "fixed source")
        self.commit = git(self.repo, "rev-parse", "HEAD")
        self.cache = self.root / "checkpoints"

    def scan(self, engine=ENGINE, detector_ids=(DETECTOR,)):
        return run_fixed_commit_scan(
            self.repo, "fixture/checkpoint", self.commit, (".",), detector_ids,
            self.root / "report.json", self.root / "report.md", allow_examples=True,
            detector_checkpoint_dir=self.cache,
            detector_checkpoint_engine_sha256=engine,
        )

    @staticmethod
    def semantic_signature(report):
        runs = json.loads(json.dumps(report["detector_runs"]))
        for run in runs:
            run.pop("elapsed_seconds", None)
        return {
            **{key: report[key] for key in (
                "repository", "commit", "git_tree", "snapshot_sha256", "status",
                "diagnostic_count", "detector_coverage", "source_parsing",
            )},
            "detector_runs": runs,
        }

    def test_completed_shard_resumes_with_identical_diagnostics_and_coverage(self):
        cold = self.scan()
        hot = self.scan()
        self.assertEqual(self.semantic_signature(cold), self.semantic_signature(hot))
        self.assertEqual(cold["performance"]["detector_checkpoints"]["writes"], 1)
        self.assertEqual(hot["performance"]["detector_checkpoints"]["hits"], 1)
        self.assertEqual(hot["performance"]["detector_execution_seconds"], 0.0)
        self.assertEqual(hot["status"], "completed_with_limitations")
        self.assertEqual(hot["detector_coverage"]["detectors"][DETECTOR]["status"], "partial")
        self.assertEqual(hot["detector_coverage"]["detectors"][DETECTOR]["partially_inspected_files"], [])
        self.assertEqual(hot["detector_coverage"]["detectors"][DETECTOR]["not_analyzed_files"],
                         ["src/partial.cpp"])

    def test_engine_change_and_corrupt_checkpoint_are_misses(self):
        self.scan()
        self.assertEqual(self.scan(engine="b" * 64)["performance"]["detector_checkpoints"]["hits"], 0)
        entries = list(self.cache.glob("*.json"))
        self.assertGreaterEqual(len(entries), 2)
        for entry in entries:
            entry.write_text("{corrupt", encoding="utf-8")
        result = self.scan(engine=ENGINE)
        self.assertEqual(result["performance"]["detector_checkpoints"]["hits"], 0)
        self.assertGreaterEqual(result["performance"]["detector_checkpoints"]["invalid"], 1)
        self.assertEqual(result["status"], "completed_with_limitations")
        self.assertEqual(result["detector_coverage"]["detectors"][DETECTOR]["status"], "partial")

    def test_source_blob_change_invalidates_completed_shard(self):
        self.scan()
        (self.repo / "src/copy.cpp").write_text(
            "void f(char* dst, char* src) { memcpy(dst, src, 20); }\n", encoding="utf-8")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "changed source blob")
        self.commit = git(self.repo, "rev-parse", "HEAD")
        changed = self.scan()
        self.assertEqual(changed["performance"]["detector_checkpoints"]["hits"], 0)
        self.assertEqual(changed["performance"]["detector_checkpoints"]["writes"], 1)

    def test_non_applicable_blocked_run_is_never_checkpointed(self):
        (self.repo / "src/copy.cpp").unlink()
        (self.repo / "src/only.js").write_text("function safe() {}\n", encoding="utf-8")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "unsupported language")
        self.commit = git(self.repo, "rev-parse", "HEAD")
        result = self.scan()
        self.assertEqual(result["detector_runs"][0]["status"], "blocked")
        self.assertEqual(result["performance"]["detector_checkpoints"]["writes"], 0)
        self.assertFalse(list(self.cache.glob("*.json")))

    def test_failed_detector_is_never_checkpointed(self):
        from src.ohscanner.detectors.example import CppCopyCallExampleDetector
        with patch.object(CppCopyCallExampleDetector, "detect",
                          side_effect=RuntimeError("injected detector failure")):
            failed = self.scan()
        self.assertEqual(failed["detector_runs"][0]["status"], "failed")
        self.assertEqual(failed["performance"]["detector_checkpoints"]["writes"], 0)
        self.assertFalse(list(self.cache.glob("*.json")))
        recovered = self.scan()
        self.assertEqual(recovered["detector_runs"][0]["status"], "completed")
        self.assertEqual(recovered["performance"]["detector_checkpoints"]["hits"], 0)


if __name__ == "__main__":
    unittest.main()
