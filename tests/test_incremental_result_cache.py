import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.ohscanner.execution import run_fixed_commit_scan
from src.ohscanner import incremental_cache

ROOT = Path(__file__).resolve().parents[1]


class IncrementalResultCacheTests(unittest.TestCase):
    def _git(self, repo, *args):
        return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()

    def _commit(self, repo, message):
        subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", message], check=True)
        return self._git(repo, "rev-parse", "HEAD")

    def _scan(self, repo, commit, out, cache=None, base=None):
        return run_fixed_commit_scan(
            repo, "fixture/incremental-cache", commit, (".",),
            ("ohscanner.example.cpp.copy-calls",),
            out / "report.json", out / "report.md", allow_examples=True,
            base_commit=base,
            detector_result_cache_dir=cache,
        )

    def _scan_m2(self, repo, commit, out, cache=None, base=None):
        return run_fixed_commit_scan(
            repo, "fixture/incremental-cache-m2", commit, (".",),
            ("ohscanner.cpp.lifetime", "ohscanner.cpp.shared_ptr_race"),
            out / "report.json", out / "report.md",
            base_commit=base,
            detector_result_cache_dir=cache,
        )

    @staticmethod
    def _identity(report):
        result = report["detector_runs"][0]
        return {
            "status": report["status"],
            "parsing": report["source_parsing"],
            "coverage": report["detector_coverage"],
            "run_status": result["status"],
            "diagnostics": sorted((row["diagnostic_id"], row["file"], row["line"], row["column"])
                                  for row in result["diagnostics"]),
        }

    def test_changed_blob_misses_unchanged_blob_hits_and_matches_uncached_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
            (repo / "a.cpp").write_text("void a(){ memcpy(x, y, n); }\n", encoding="utf-8")
            (repo / "b.cpp").write_text("void b(){ memcpy(x, y, n); }\n", encoding="utf-8")
            base = self._commit(repo, "base")
            cache = root / "cache"

            cold = self._scan(repo, base, root / "cold", cache)
            self.assertEqual(cold["performance"]["detector_result_cache"]["writes"], 2)
            self.assertEqual(cold["performance"]["detector_result_cache"]["hits"], 0)

            (repo / "a.cpp").write_text("void a(){ memcpy(x, y, n); memcpy(z, q, m); }\n", encoding="utf-8")
            head = self._commit(repo, "change a")
            cached = self._scan(repo, head, root / "cached", cache, base)
            uncached = self._scan(repo, head, root / "uncached")
            stats = cached["performance"]["detector_result_cache"]
            self.assertEqual(stats["hits"], 1)
            self.assertEqual(stats["writes"], 1)
            self.assertEqual(self._identity(cached), self._identity(uncached))
            self.assertEqual(cached["incremental"]["execution"],
                             "full_source_index_with_verified_per_file_result_reuse")
            self.assertEqual(cached["incremental"]["reused_files"], 1)
            saved = json.loads((root / "cached" / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["performance"]["detector_result_cache"]["hits"], 1)

    def test_corrupt_entry_falls_back_to_detection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
            (repo / "a.cpp").write_text("void a(){ memcpy(x, y, n); }\n", encoding="utf-8")
            commit = self._commit(repo, "base")
            cache = root / "cache"
            self._scan(repo, commit, root / "first", cache)
            entry = next(cache.glob("[0-9a-f]*.json"))
            entry.write_text("{broken", encoding="utf-8")
            rerun = self._scan(repo, commit, root / "rerun", cache)
            stats = rerun["performance"]["detector_result_cache"]
            self.assertEqual(stats["hits"], 0)
            self.assertEqual(stats["invalid"], 1)
            self.assertEqual(stats["writes"], 1)
            self.assertEqual(rerun["status"], "completed")

    def test_parser_fingerprint_change_misses_prior_result(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
            (repo / "a.cpp").write_text("void a(){ memcpy(x, y, n); }\n", encoding="utf-8")
            commit = self._commit(repo, "base")
            cache = root / "cache"
            self._scan(repo, commit, root / "first", cache)
            actual = incremental_cache.parser_fingerprint("cpp")
            with patch.object(incremental_cache, "parser_fingerprint",
                              return_value={**actual, "tree-sitter-cpp": "unavailable-next-version"}):
                rerun = self._scan(repo, commit, root / "changed-parser", cache)
            stats = rerun["performance"]["detector_result_cache"]
            self.assertEqual(stats["hits"], 0)
            self.assertEqual(stats["misses"], 1)
            self.assertEqual(stats["writes"], 1)

    def test_engine_source_fingerprint_change_misses_prior_result(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
            (repo / "a.cpp").write_text("void a(){ memcpy(x, y, n); }\n", encoding="utf-8")
            commit = self._commit(repo, "base")
            cache = root / "cache"
            self._scan(repo, commit, root / "first", cache)
            with patch.object(incremental_cache, "_engine_fingerprint", return_value="f" * 64):
                changed = self._scan(repo, commit, root / "changed-engine", cache)
            stats = changed["performance"]["detector_result_cache"]
            self.assertEqual(stats["hits"], 0)
            self.assertEqual(stats["misses"], 1)
            self.assertEqual(stats["writes"], 1)

    def test_m2_single_file_adapters_reuse_only_completed_per_file_results(self):
        fixtures = ROOT / "tests" / "detectors" / "fixtures"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            (repo / "src").mkdir(parents=True)
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
            samples = {
                "src/lifetime.cpp": fixtures / "cpp_lifetime" / "vulnerable_unserialized.cpp",
                "src/race.cpp": fixtures / "cpp_shared_ptr_race" / "vulnerable_non_atomic_shared_ptr.cpp",
                "src/safe.cpp": fixtures / "cpp_lifetime" / "fixed_alias_rebind.cpp",
                "src/partial.cpp": None,
            }
            for relative, source in samples.items():
                text = "int invalid( {\n" if source is None else source.read_text(encoding="utf-8")
                (repo / relative).write_text(text, encoding="utf-8")
            commit = self._commit(repo, "M2 immutable fixture")
            cache = root / "cache"
            cold = self._scan_m2(repo, commit, root / "cold", cache)
            cold_stats = cold["performance"]["detector_result_cache"]
            self.assertEqual(cold_stats["hits"], 0)
            self.assertGreater(cold_stats["writes"], 0)

            safe_path = repo / "src" / "safe.cpp"
            safe_path.write_text(safe_path.read_text(encoding="utf-8") + "\n// harmless source-only edit\n",
                                 encoding="utf-8")
            head = self._commit(repo, "edit fixed source comment")
            hot = self._scan_m2(repo, head, root / "hot", cache, base=commit)
            # Explicit base planning remains conservative and reports full
            # fallback; unchanged, complete per-file M2 results can still be
            # reused by their verified Blob identity.
            hot_stats = hot["performance"]["detector_result_cache"]
            uncached = self._scan_m2(repo, head, root / "uncached")
            self.assertGreater(hot_stats["hits"], 0)
            self.assertLess(hot_stats["hits"], cold_stats["writes"])
            self.assertNotIn("src/safe.cpp", hot_stats["hit_paths"])
            self.assertEqual(hot["incremental"]["fallback"], True)
            self.assertEqual(hot["incremental"]["execution"],
                             "full_source_index_with_verified_per_file_result_reuse")
            self.assertEqual(hot["status"], uncached["status"])
            self.assertEqual(hot["status"], "completed_with_limitations")
            self.assertEqual(hot["source_parsing"], uncached["source_parsing"])
            self.assertEqual(hot["detector_coverage"], uncached["detector_coverage"])
            self.assertEqual(
                [
                    (row["tool"], row["status"], row["diagnostics"])
                    for row in hot["detector_runs"]
                ],
                [
                    (row["tool"], row["status"], row["diagnostics"])
                    for row in uncached["detector_runs"]
                ],
            )
            self.assertGreater(
                sum(row["diagnostic_count"] for row in hot["detector_runs"]), 0
            )


if __name__ == "__main__":
    unittest.main()
