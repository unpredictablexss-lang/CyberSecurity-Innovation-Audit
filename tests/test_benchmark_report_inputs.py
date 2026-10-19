import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path

from src.benchmark.historical import HistoricalSample
from src.benchmark.report_inputs import DEFAULT_TOOLS, load_report_runs
from src.benchmark.root_cause_matrix import build_revision_hit_matrix
from src.report.benchmark_report import build_benchmark_report, render_markdown


REPO_ROOT = Path(__file__).resolve().parents[1]


def sample(sample_id="seed"):
    return HistoricalSample(
        schema_version=1, sample_id=sample_id, title="test seed", repository="repo",
        repo_url="https://example.com/repo", vulnerable_commit="a" * 40,
        fixed_commit="b" * 40, weakness="CWE-476", affected_files=["src/f.cpp"],
        affected_symbols=["target"], root_cause="test root cause", root_cause_group="null_deref",
    )


def normalized(seed, revision="vulnerable", status="completed", diagnostics=None, tool="joern"):
    return {
        "schema_version": 1, "run_id": f"{tool}-{revision}", "tool": tool,
        "tool_version": "test", "target_id": seed.sample_id,
        "commit": getattr(seed, f"{revision}_commit"), "scope_files": 1,
        "scope_loc": 20, "status": status, "elapsed_seconds": 0.1,
        "diagnostics": diagnostics or [], "limitations": ["syntactic evidence only"],
    }


def diagnostic(symbol="target"):
    return {
        "diagnostic_id": "d1", "provider": "joern", "evidence_type": "syntax",
        "file": "src/f.cpp", "line": 3, "column": None, "rule_id": "test-rule",
        "severity": "warning", "message": "test candidate", "symbol": symbol,
    }


class BenchmarkInputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.seed = sample()

    def manifest(self, payload, revision="vulnerable", **entry_fields):
        report = self.root / f"{revision}.json"
        report.write_text(json.dumps(payload), encoding="utf-8")
        entry = {"sample_id": self.seed.sample_id, "revision": revision,
                 "report": report.name, "analyzed_files": ["src/f.cpp"], **entry_fields}
        path = self.root / "inputs.json"
        path.write_text(json.dumps({"schema_version": 1, "runs": [entry]}), encoding="utf-8")
        return path

    def test_saved_run_preserves_revision_provenance_and_joern_symbol(self):
        path = self.manifest(normalized(self.seed, diagnostics=[diagnostic()]))
        runs = load_report_runs(path, [self.seed])
        matrix = build_revision_hit_matrix([self.seed], runs, tools=["joern"])
        vulnerable, fixed = matrix.rows
        self.assertEqual((vulnerable.status, fixed.status), ("possible_hit", "unknown"))
        self.assertEqual(vulnerable.source_sha256, hashlib.sha256((self.root / "vulnerable.json").read_bytes()).hexdigest())
        self.assertEqual(vulnerable.analyzed_files, ("src/f.cpp",))
        self.assertEqual(vulnerable.limitations, ("syntactic evidence only",))
        self.assertEqual(vulnerable.commit, self.seed.vulnerable_commit)

    def test_same_file_symbol_in_another_sample_does_not_leak(self):
        runs = load_report_runs(self.manifest(normalized(self.seed, diagnostics=[diagnostic()])), [self.seed])
        matrix = build_revision_hit_matrix([self.seed, sample("other")], runs, tools=["joern"])
        self.assertTrue(all(row.status == "unknown" for row in matrix.rows if row.sample_id == "other"))

    def test_fixed_completed_empty_report_is_miss_only_for_fixed(self):
        runs = load_report_runs(self.manifest(normalized(self.seed, "fixed"), revision="fixed"), [self.seed])
        rows = build_revision_hit_matrix([self.seed], runs, tools=["joern"]).rows
        self.assertEqual([row.status for row in rows], ["unknown", "miss"])

    def test_rejects_wrong_revision_commit_and_target(self):
        for field, value in (("commit", self.seed.fixed_commit), ("target_id", "other")):
            with self.subTest(field=field):
                payload = normalized(self.seed)
                payload[field] = value
                with self.assertRaisesRegex(ValueError, "mismatch|target_id"):
                    load_report_runs(self.manifest(payload), [self.seed])

    def test_duplicate_run_is_rejected_instead_of_overwriting(self):
        runs = load_report_runs(self.manifest(normalized(self.seed)), [self.seed])
        with self.assertRaisesRegex(ValueError, "duplicate benchmark run"):
            build_revision_hit_matrix([self.seed], runs + runs)

    def test_failed_empty_run_is_unknown_not_miss(self):
        runs = load_report_runs(self.manifest(normalized(self.seed, status="failed"), reason="timeout"), [self.seed])
        row = build_revision_hit_matrix([self.seed], runs).rows[0]
        self.assertEqual(row.status, "unknown")
        self.assertEqual(row.reason, "timeout")

    def test_incompatible_run_reason_survives_json_and_markdown(self):
        runs = load_report_runs(self.manifest(normalized(self.seed, status="failed", tool="clang_sa"),
                                             not_applicable_reason="missing headers"), [self.seed])
        report = build_benchmark_report([self.seed], runs=runs, tools=DEFAULT_TOOLS)
        rows = report.to_dict()["root_cause_matrix"]["rows"]
        row = next(row for row in rows if row["tool"] == "clang_sa" and row["revision"] == "vulnerable")
        self.assertEqual(row["status"], "not_applicable")
        self.assertIn("missing headers", render_markdown(report))

    def test_not_applicable_requires_failed_run_and_reason(self):
        with self.assertRaisesRegex(ValueError, "cannot be not_applicable"):
            load_report_runs(self.manifest(normalized(self.seed), not_applicable_reason="not supported"), [self.seed])
        with self.assertRaisesRegex(ValueError, "explicit reason"):
            load_report_runs(self.manifest(normalized(self.seed, status="blocked")), [self.seed])

    def test_unresolved_symbol_is_unknown_not_miss(self):
        runs = load_report_runs(self.manifest(normalized(self.seed, diagnostics=[diagnostic(None)])), [self.seed])
        row = build_revision_hit_matrix([self.seed], runs).rows[0]
        self.assertEqual(row.status, "unknown")
        self.assertIn("unresolved", row.reason)

    def test_saved_reports_cannot_escape_manifest_directory(self):
        path = self.manifest(normalized(self.seed))
        original = json.loads(path.read_text(encoding="utf-8"))
        for report_name in ("../outside.json", str(self.root.parent / "outside.json")):
            with self.subTest(report=report_name):
                entry = dict(original["runs"][0], report=report_name)
                path.write_text(json.dumps({"schema_version": 1, "runs": [entry]}), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "within the manifest directory"):
                    load_report_runs(path, [self.seed])

    def test_rejects_changed_source_hash(self):
        with self.assertRaisesRegex(ValueError, "sha256 mismatch"):
            load_report_runs(self.manifest(normalized(self.seed), sha256="0" * 64), [self.seed])

    def test_rejects_malformed_locations_and_missing_scope(self):
        for value in ("../f.cpp", "/tmp/f.cpp", "C:\\snapshot\\f.cpp", None):
            with self.subTest(value=value):
                item = diagnostic()
                item["file"] = value
                with self.assertRaises(ValueError):
                    load_report_runs(self.manifest(normalized(self.seed, diagnostics=[item])), [self.seed])
        with self.assertRaisesRegex(ValueError, "requires analyzed_files"):
            load_report_runs(self.manifest(normalized(self.seed), analyzed_files=None), [self.seed])

    def test_cli_rejects_wrong_commit_without_creating_reports(self):
        samples_dir = self.root / "samples"
        samples_dir.mkdir()
        (samples_dir / "seed.json").write_text(json.dumps(asdict(self.seed)), encoding="utf-8")
        payload = normalized(self.seed)
        payload["commit"] = self.seed.fixed_commit
        manifest = self.manifest(payload)
        json_out, md_out = self.root / "bad.json", self.root / "bad.md"
        process = subprocess.run([
            sys.executable, "-m", "src.cli", "benchmark-report", "--samples-dir", str(samples_dir),
            "--results", str(manifest), "--json-out", str(json_out), "--md-out", str(md_out),
        ], cwd=REPO_ROOT, capture_output=True, text=True)
        self.assertEqual(process.returncode, 2)
        self.assertIn("commit mismatch", process.stderr)
        self.assertFalse(json_out.exists())
        self.assertFalse(md_out.exists())

    def test_missing_affected_file_scope_is_unknown(self):
        runs = load_report_runs(self.manifest(normalized(self.seed), analyzed_files=["other.cpp"]), [self.seed])
        row = build_revision_hit_matrix([self.seed], runs).rows[0]
        self.assertEqual(row.status, "unknown")
        self.assertIn("scope", row.reason)

    def test_candidate_outside_declared_scope_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "outside analyzed_files"):
            load_report_runs(self.manifest(normalized(self.seed, diagnostics=[diagnostic()]),
                                          analyzed_files=["other.cpp"]), [self.seed])

    def test_historical_replay_imports_only_recorded_text_results(self):
        payload = {"sample": asdict(self.seed), "replay_status": "metadata_and_static_replay_verified",
                   "vulnerable": {"commit": self.seed.vulnerable_commit, "candidate_count": 1,
                                  "candidates": [{"file": "src/f.cpp", "function": "target", "line": 3}]}}
        runs = load_report_runs(self.manifest(payload, format="historical"), [self.seed])
        report = build_benchmark_report([self.seed], runs=runs, tools=["own_text", "own_ast"])
        self.assertEqual(next(row.status for row in report.root_cause_matrix.rows
                             if row.tool == "own_text" and row.revision == "vulnerable"), "possible_hit")
        self.assertTrue(all(row.status == "unknown" for row in report.root_cause_matrix.rows if row.tool == "own_ast"))

    def test_cli_consumes_saved_runs_and_defaults_missing_runs_to_unknown(self):
        samples_dir = self.root / "samples"
        samples_dir.mkdir()
        (samples_dir / "seed.json").write_text(json.dumps(asdict(self.seed)), encoding="utf-8")
        path = self.manifest(normalized(self.seed, diagnostics=[diagnostic()]))
        for supplied in (True, False):
            with self.subTest(supplied=supplied):
                json_out, md_out = self.root / "summary.json", self.root / "summary.md"
                args = [sys.executable, "-m", "src.cli", "benchmark-report",
                        "--samples-dir", str(samples_dir), "--json-out", str(json_out), "--md-out", str(md_out)]
                if supplied:
                    args.extend(["--results", str(path)])
                process = subprocess.run(args, cwd=REPO_ROOT, capture_output=True, text=True)
                self.assertEqual(process.returncode, 0, process.stderr)
                result = json.loads(json_out.read_text(encoding="utf-8"))
                row = next(row for row in result["root_cause_matrix"]["rows"]
                           if row["tool"] == "joern" and row["revision"] == "vulnerable")
                self.assertEqual(row["status"], "possible_hit" if supplied else "unknown")
                self.assertEqual(result["validated_vulnerability"], 0)
                markdown = md_out.read_text(encoding="utf-8")
                self.assertIn("1 samples", markdown)
                self.assertNotIn("Only 3", markdown)


if __name__ == "__main__":
    unittest.main()
