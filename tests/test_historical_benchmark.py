import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from src.benchmark.historical import (
    load_sample,
    run_historical_benchmark,
    write_reports,
)


class HistoricalBenchmarkTests(unittest.TestCase):
    def _git(self, repo: Path, *args: str) -> str:
        process = subprocess.run(
            ["git", "-C", str(repo), *args],
            text=True,
            capture_output=True,
            check=False,
        )
        if process.returncode != 0:
            self.fail(process.stderr or process.stdout)
        return process.stdout.strip()

    def _build_fixture(self, directory: Path):
        repo = directory / "fixture_repo"
        repo.mkdir()
        self._git(repo, "init")
        self._git(repo, "config", "user.email", "tests@example.invalid")
        self._git(repo, "config", "user.name", "Benchmark Tests")

        source = repo / "src" / "demo.c"
        source.parent.mkdir(parents=True)
        source.write_text(
            "#include <string.h>\n"
            "void copy(char *dst, const char *src) {\n"
            "    strcpy(dst, src);\n"
            "}\n",
            encoding="utf-8",
        )
        self._git(repo, "add", ".")
        self._git(repo, "commit", "-m", "vulnerable revision")
        vulnerable = self._git(repo, "rev-parse", "HEAD")

        source.write_text(
            "void copy(char *dst, const char *src) {\n"
            "    while (*src != '\\0') { *dst++ = *src++; }\n"
            "    *dst = '\\0';\n"
            "}\n",
            encoding="utf-8",
        )
        self._git(repo, "add", ".")
        self._git(repo, "commit", "-m", "fix unsafe copy")
        fixed = self._git(repo, "rev-parse", "HEAD")

        manifest = directory / "sample.json"
        manifest.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "sample_id": "fixture-copy",
                    "title": "Fixture unsafe copy",
                    "repository": "fixture/repo",
                    "repo_url": "https://example.invalid/fixture/repo",
                    "vulnerable_commit": vulnerable,
                    "fixed_commit": fixed,
                    "weakness": "CWE-120",
                    "affected_files": ["src/demo.c"],
                    "affected_symbols": ["copy"],
                    "root_cause": "unbounded string copy",
                    "source_refs": [],
                }
            ),
            encoding="utf-8",
        )
        return repo, manifest, vulnerable, fixed

    def test_load_sample_rejects_missing_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text('{"schema_version": 1}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "missing fields"):
                load_sample(path)

    def test_replay_verifies_pair_and_exposes_candidate_delta(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, manifest, vulnerable, fixed = self._build_fixture(Path(directory))
            result = run_historical_benchmark(manifest, repo)

        self.assertEqual(result.sample.sample_id, "fixture-copy")
        self.assertTrue(result.vulnerable_commit_exists)
        self.assertTrue(result.fixed_commit_exists)
        self.assertTrue(result.direct_parent_match)
        self.assertEqual(result.affected_files_changed, ["src/demo.c"])
        self.assertEqual(result.vulnerable.commit, vulnerable)
        self.assertEqual(result.fixed.commit, fixed)
        self.assertEqual(result.vulnerable.candidate_count, 1)
        self.assertEqual(result.fixed.candidate_count, 0)
        self.assertTrue(result.text_candidate_overlap_in_vulnerable)
        self.assertFalse(result.text_candidate_overlap_in_fixed)
        self.assertIn("copy", result.vulnerable.affected_symbols_present)
        self.assertIn("copy", result.fixed.affected_symbols_present)

    def test_missing_commit_is_reported_instead_of_guessed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, manifest, _, _ = self._build_fixture(Path(directory))
            data = json.loads(manifest.read_text(encoding="utf-8"))
            data["vulnerable_commit"] = "0" * 40
            manifest.write_text(json.dumps(data), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "vulnerable commit is not available"):
                run_historical_benchmark(manifest, repo)

    def test_reports_keep_historical_ground_truth_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, manifest, _, _ = self._build_fixture(root)
            result = run_historical_benchmark(manifest, repo)
            json_output = root / "report.json"
            md_output = root / "report.md"
            write_reports(result, json_output, md_output)

            data = json.loads(json_output.read_text(encoding="utf-8"))
            markdown = md_output.read_text(encoding="utf-8")

        self.assertEqual(
            data["replay_status"],
            "metadata_and_static_replay_verified",
        )
        self.assertEqual(data["runtime_validation"], "not_run")
        self.assertIn("Historical ground truth only", data["interpretation"])
        self.assertIn("does not claim a new vulnerability", markdown)
        self.assertIn("No precision is computed", markdown)


    def test_cli_writes_historical_reports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, manifest, _, _ = self._build_fixture(root)
            json_output = root / "cli-report.json"
            md_output = root / "cli-report.md"
            project_root = Path(__file__).resolve().parents[1]

            process = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "src.cli",
                    "benchmark-historical",
                    "--sample",
                    str(manifest),
                    "--repo-dir",
                    str(repo),
                    "--json-out",
                    str(json_output),
                    "--md-out",
                    str(md_output),
                ],
                cwd=project_root,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(process.returncode, 0, process.stderr)
            data = json.loads(json_output.read_text(encoding="utf-8"))
            markdown = md_output.read_text(encoding="utf-8")

        self.assertEqual(data["sample"]["sample_id"], "fixture-copy")
        self.assertIn("[OK] historical sample: fixture-copy", process.stdout)
        self.assertIn("Historical Vulnerability Benchmark Replay", markdown)



if __name__ == "__main__":
    unittest.main()
