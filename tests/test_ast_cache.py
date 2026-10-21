import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from src.ohscanner.ast_cache import AstSummaryCache, cache_identity
from src.ohscanner.frontend import index_sources
from src.ohscanner.git_source import GitSource
from src.parser.ast import parse_source


def blob_oid(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


class AstSummaryCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.cache_dir = Path(self.temp.name) / "cache"
        self.data = b"int copy(char *p) { memcpy(p, p, 4); return 0; }\n"
        self.source = GitSource("src/a.cpp", "cpp", blob_oid(self.data), self.data)

    def test_cold_then_hot_reuses_identical_single_file_ast(self):
        cold_metrics = {}
        cold_cache = AstSummaryCache(self.cache_dir)
        cold = index_sources((self.source,), cold_cache, cold_metrics)
        self.assertEqual(cold_cache.stats["misses"], 1)
        self.assertEqual(cold_cache.stats["writes"], 1)
        self.assertEqual(cold_metrics["parse_files"], 1)

        hot_metrics = {}
        hot_cache = AstSummaryCache(self.cache_dir)
        hot = index_sources((self.source,), hot_cache, hot_metrics)
        self.assertEqual(hot_cache.stats["hits"], 1)
        self.assertEqual(hot_metrics["parse_files"], 0)
        self.assertEqual(cold[0], hot[0])
        self.assertEqual(cold[1], hot[1])
        self.assertEqual(cold[2], hot[2])

    def test_changed_blob_and_language_do_not_reuse_cached_ast(self):
        cache = AstSummaryCache(self.cache_dir)
        index_sources((self.source,), cache)
        changed = b"int copy(char *p) { return 1; }\n"
        changed_source = GitSource("src/a.cpp", "cpp", blob_oid(changed), changed)
        fresh = AstSummaryCache(self.cache_dir)
        result = index_sources((changed_source,), fresh)
        self.assertEqual(fresh.stats["misses"], 1)
        self.assertEqual(result[1]["src/a.cpp"]["calls"], [])

        language_cache = AstSummaryCache(self.cache_dir)
        index_sources((GitSource("src/a.cpp", "c", self.source.oid, self.data),), language_cache)
        self.assertEqual(language_cache.stats["misses"], 1)

    def test_parser_version_change_invalidates_cache(self):
        identity = cache_identity(self.source.oid, self.source.language, self.data)
        self.assertIsNotNone(identity)
        cache = AstSummaryCache(self.cache_dir)
        index_sources((self.source,), cache)
        with patch("src.ohscanner.ast_cache.parser_fingerprint",
                   return_value={"tree-sitter": "different", "ast_parser_spec": "light-ast-v1"}):
            changed = AstSummaryCache(self.cache_dir)
            self.assertIsNone(changed.load(self.source.oid, self.source.language, self.data))
            self.assertEqual(changed.stats["misses"], 1)

    def test_corrupt_cache_falls_back_to_parse(self):
        cache = AstSummaryCache(self.cache_dir)
        index_sources((self.source,), cache)
        identity = cache_identity(self.source.oid, self.source.language, self.data)
        cache._path(identity).write_text("{broken", encoding="utf-8")
        retry = AstSummaryCache(self.cache_dir)
        metrics = {}
        result = index_sources((self.source,), retry, metrics)
        self.assertEqual(retry.stats["invalid"], 1)
        self.assertEqual(metrics["parse_files"], 1)
        self.assertEqual(result[0][0].parse_status, "complete")

    def test_failed_parse_is_not_cached_or_upgraded_on_retry(self):
        cache = AstSummaryCache(self.cache_dir)
        with patch("src.ohscanner.frontend.parse_source", side_effect=RuntimeError("parser failed")):
            failed = index_sources((self.source,), cache)
        self.assertEqual(failed[0][0].parse_status, "failed")
        retry_cache = AstSummaryCache(self.cache_dir)
        retry = index_sources((self.source,), retry_cache)
        self.assertEqual(retry_cache.stats["hits"], 0)
        self.assertEqual(retry[0][0].parse_status, "complete")
        self.assertEqual(parse_source(self.data.decode(), "cpp").parse_status, "complete")

    def test_invalid_oid_and_archive_member_bypass_cache(self):
        invalid = GitSource("src/fake.cpp", "cpp", "f" * 40, self.data)
        archive = GitSource("bundle.tar.gz.members/src/a.cpp", "cpp", self.source.oid,
                            self.data, {"archive_path": "bundle.tar.gz"})
        cache = AstSummaryCache(self.cache_dir)
        index_sources((invalid, archive), cache)
        self.assertEqual(cache.stats["bypassed"], 2)
        self.assertEqual(cache.stats["hits"], 0)

    def test_cache_limit_evicts_old_entries_and_clear_preserves_unrelated_files(self):
        cache = AstSummaryCache(self.cache_dir, max_bytes=1024 * 1024)
        index_sources((self.source,), cache)
        first_identity = cache_identity(self.source.oid, self.source.language, self.data)
        first_path = cache._path(first_identity)
        first_size = first_path.stat().st_size
        unrelated = self.cache_dir / "notes.txt"
        unrelated.write_text("keep", encoding="utf-8")

        changed = self.data.replace(b"copy", b"cop2")
        second_source = GitSource("src/b.cpp", "cpp", blob_oid(changed), changed)
        second_identity = cache_identity(second_source.oid, second_source.language, changed)
        second_path = cache._path(second_identity)
        # Make the ordering deterministic: the first entry is the oldest.
        first_path.touch()
        os.utime(first_path, ns=(1, 1))
        cache.max_bytes = first_size
        index_sources((second_source,), cache)
        self.assertFalse(first_path.exists())
        self.assertTrue(second_path.exists())
        self.assertLessEqual(cache.report_stats()["cache_bytes"], first_size)
        self.assertGreaterEqual(cache.stats["evictions"], 1)

        cleared = cache.clear()
        self.assertEqual(cleared["entries"], 1)
        self.assertFalse(second_path.exists())
        self.assertEqual(unrelated.read_text(encoding="utf-8"), "keep")

    def test_oversize_entry_is_not_stored_but_parse_result_is_kept(self):
        source = GitSource("src/large.cpp", "cpp", blob_oid(self.data), self.data)
        cache = AstSummaryCache(self.cache_dir, max_bytes=0)
        result = index_sources((source,), cache)
        self.assertEqual(result[0][0].parse_status, "complete")
        self.assertEqual(cache.stats["oversize_not_stored"], 1)
        self.assertEqual(cache.report_stats()["cache_bytes"], 0)
        retry = AstSummaryCache(self.cache_dir, max_bytes=0)
        index_sources((source,), retry)
        self.assertEqual(retry.stats["misses"], 1)

    def test_partial_ast_round_trips_without_becoming_complete(self):
        data = b"int incomplete( { memcpy(dst, src, 4);\n"
        source = GitSource("src/partial.cpp", "cpp", blob_oid(data), data)
        cold_cache = AstSummaryCache(self.cache_dir)
        cold = index_sources((source,), cold_cache)
        self.assertEqual(cold[0][0].parse_status, "partial")
        hot_cache = AstSummaryCache(self.cache_dir)
        hot = index_sources((source,), hot_cache)
        self.assertEqual(hot_cache.stats["hits"], 1)
        self.assertEqual(hot[0][0].parse_status, "partial")
        self.assertEqual(cold[1], hot[1])

    def test_cold_and_hot_m2_results_keep_candidates_and_partial_coverage(self):
        from src.ohscanner.execution import run_fixed_commit_scan

        repo = Path(self.temp.name) / "repo"
        repo.mkdir()
        def git(*args):
            return subprocess.run(["git", "-C", str(repo), *args], check=True,
                                  capture_output=True, text=True, timeout=20).stdout.strip()
        git("init", "-q")
        git("config", "user.email", "cache-test@example.invalid")
        git("config", "user.name", "Cache Test")
        (repo / "src").mkdir()
        (repo / "src" / "candidate.cpp").write_text(
            "void f(char *p) { memcpy(p, p, 4); }\n", encoding="utf-8")
        (repo / "src" / "partial.cpp").write_text(
            "int broken( { memcpy(dst, src, 4);\n", encoding="utf-8")
        git("add", "-A")
        git("commit", "-qm", "cache fixture")
        commit = git("rev-parse", "HEAD")
        cache_dir = Path(self.temp.name) / "m2-cache"

        def run(label):
            return run_fixed_commit_scan(
                repo, "fixture/cache-test", commit, (".",),
                ("ohscanner.example.cpp.copy-calls",),
                Path(self.temp.name) / f"{label}.json",
                Path(self.temp.name) / f"{label}.md",
                allow_examples=True, ast_cache_dir=cache_dir)

        cold, hot = run("cold"), run("hot")
        self.assertEqual(cold["status"], hot["status"])
        self.assertEqual(cold["detector_runs"][0]["diagnostics"],
                         hot["detector_runs"][0]["diagnostics"])
        self.assertEqual(cold["detector_coverage"], hot["detector_coverage"])
        self.assertEqual(cold["source_parsing"], hot["source_parsing"])
        self.assertEqual(cold["performance"]["ast_cache"]["misses"], 2)
        self.assertEqual(hot["performance"]["ast_cache"]["hits"], 2)
        self.assertEqual(hot["source_parsing"]["parsing_status"]["partial"], 1)


    def test_corrupt_cache_does_not_upgrade_blocked_detector_coverage(self):
        from src.ohscanner.execution import run_fixed_commit_scan

        repo = Path(self.temp.name) / "blocked-repo"
        repo.mkdir()
        def git(*args):
            return subprocess.run(["git", "-C", str(repo), *args], check=True,
                                  capture_output=True, text=True, timeout=20).stdout.strip()
        git("init", "-q")
        git("config", "user.email", "cache-test@example.invalid")
        git("config", "user.name", "Cache Test")
        (repo / "src").mkdir()
        partial_data = b"int incomplete( { memcpy(dst, src, 4);\n"
        (repo / "src" / "partial.cpp").write_bytes(partial_data)
        git("add", "-A")
        git("commit", "-qm", "partial-only fixture")
        commit = git("rev-parse", "HEAD")
        cache_dir = Path(self.temp.name) / "blocked-cache"

        def run(label):
            return run_fixed_commit_scan(
                repo, "fixture/blocked-cache-test", commit, (".",),
                ("ohscanner.example.cpp.copy-calls",),
                Path(self.temp.name) / f"blocked-{label}.json",
                Path(self.temp.name) / f"blocked-{label}.md",
                allow_examples=True, ast_cache_dir=cache_dir)

        cold = run("cold")
        self.assertEqual(cold["detector_runs"][0]["status"], "blocked")
        self.assertEqual(cold["detector_coverage"]["detectors"][
            "ohscanner.example.cpp.copy-calls"]["status"], "blocked")
        self.assertEqual(cold["source_parsing"]["parsing_status"], {"partial": 1})

        identity = cache_identity(git("rev-parse", "HEAD:src/partial.cpp"), "cpp", partial_data)
        broken_cache = AstSummaryCache(cache_dir)
        broken_cache._path(identity).write_text("{broken", encoding="utf-8")
        recovered = run("corrupt")
        self.assertEqual(recovered["performance"]["ast_cache"]["invalid"], 1)
        self.assertEqual(recovered["performance"]["parse_files"], 1)
        self.assertEqual(recovered["detector_runs"][0]["status"], "blocked")
        self.assertEqual(recovered["detector_coverage"]["detectors"][
            "ohscanner.example.cpp.copy-calls"]["status"], "blocked")
        self.assertEqual(recovered["source_parsing"]["parsing_status"], {"partial": 1})

        hot = run("hot")
        self.assertEqual(hot["performance"]["ast_cache"]["hits"], 1)
        self.assertEqual(hot["detector_runs"][0]["status"], "blocked")
        self.assertEqual(hot["detector_coverage"]["detectors"][
            "ohscanner.example.cpp.copy-calls"]["status"], "blocked")
        self.assertEqual(cold["detector_runs"][0]["diagnostics"], [])
        self.assertEqual(cold["detector_runs"][0]["diagnostics"],
                         recovered["detector_runs"][0]["diagnostics"])

    def test_explicit_cache_clear_is_reported_before_rewarming(self):
        from src.ohscanner.execution import run_fixed_commit_scan

        repo = Path(self.temp.name) / "clear-repo"
        repo.mkdir()
        def git(*args):
            return subprocess.run(["git", "-C", str(repo), *args], check=True,
                                  capture_output=True, text=True, timeout=20).stdout.strip()
        git("init", "-q")
        git("config", "user.email", "cache-test@example.invalid")
        git("config", "user.name", "Cache Test")
        (repo / "src").mkdir()
        (repo / "src" / "one.cpp").write_text("int one() { return 1; }\n", encoding="utf-8")
        git("add", "-A")
        git("commit", "-qm", "clear fixture")
        commit = git("rev-parse", "HEAD")
        cache_dir = Path(self.temp.name) / "clear-cache"

        def run(label, clear=False):
            return run_fixed_commit_scan(
                repo, "fixture/cache-clear", commit, (".",),
                ("ohscanner.example.cpp.copy-calls",),
                Path(self.temp.name) / f"clear-{label}.json",
                Path(self.temp.name) / f"clear-{label}.md",
                allow_examples=True, ast_cache_dir=cache_dir,
                ast_cache_max_bytes=1024 * 1024, clear_ast_cache=clear)

        run("seed")
        cleared = run("requested", clear=True)
        self.assertEqual(cleared["performance"]["ast_cache"]["cleared_entries"], 1)
        self.assertEqual(cleared["performance"]["ast_cache"]["misses"], 1)
        self.assertIsNotNone(cleared["performance"]["ast_cache"]["hit_rate"])
        self.assertGreaterEqual(cleared["performance"]["source_read_cpu_seconds"], 0)
        self.assertGreaterEqual(cleared["performance"]["ast_cache_setup_seconds"], 0)
        self.assertGreaterEqual(cleared["performance"]["ast_cache_setup_cpu_seconds"], 0)
        self.assertGreaterEqual(cleared["performance"]["ast_parse_cpu_seconds"], 0)
        self.assertGreaterEqual(cleared["performance"]["facts_build_cpu_seconds"], 0)
        self.assertGreaterEqual(cleared["performance"]["detector_stage_cpu_seconds"], 0)
        self.assertGreaterEqual(cleared["performance"]["report_json_serialization_seconds"], 0)
        self.assertGreaterEqual(cleared["performance"]["report_file_write_seconds"], 0)
        self.assertEqual(cleared["performance"]["report_write_seconds"],
                         cleared["performance"]["report_file_write_seconds"])
        saved = json.loads((Path(self.temp.name) / "clear-requested.json").read_text())
        self.assertGreaterEqual(saved["performance"]["report_json_serialization_seconds"], 0)
        self.assertEqual(saved["performance"]["report_file_write_seconds"],
                         cleared["performance"]["report_file_write_seconds"])
        self.assertEqual(saved["performance"]["report_write_seconds"],
                         saved["performance"]["report_file_write_seconds"])


if __name__ == "__main__":
    unittest.main()
