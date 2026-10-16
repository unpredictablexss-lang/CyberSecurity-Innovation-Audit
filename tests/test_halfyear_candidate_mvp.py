"""Regression tests for the bounded half-year changed-source candidate MVP."""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from src.ohscanner.halfyear import (
    run_halfyear_candidate_mvp,
    select_window,
)


def git(repo, *args, env=None):
    done = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        check=True,
        text=True,
        timeout=30,
        env=env,
    )
    return done.stdout.strip()


def git_bytes(repo, *args):
    done = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        check=True,
        timeout=30,
    )
    return done.stdout


class HalfYearCandidateMvpTests(unittest.TestCase):
    detector_id = "ohscanner.interface.ipc"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repository"
        self.repo.mkdir()
        git(self.repo, "init", "-q")
        git(self.repo, "config", "user.email", "mvp@example.invalid")
        git(self.repo, "config", "user.name", "MVP CI")
        (self.repo / "src").mkdir()
        (self.repo / "src" / "sample.cpp").write_text(
            "int initial() { return 0; }\n", encoding="utf-8"
        )
        (self.repo / "README.md").write_text("initial\n", encoding="utf-8")
        self.initial = self._commit("initial", "2026-01-01T00:00:00+00:00")

        (self.repo / "src" / "sample.cpp").write_text(
            "int sample() { return 1; }\n", encoding="utf-8"
        )
        self.may = self._commit("may source", "2026-05-01T00:00:00+00:00")

        (self.repo / "README.md").write_text("documented\n", encoding="utf-8")
        self.june = self._commit("june docs", "2026-06-01T00:00:00+00:00")

        (self.repo / "src" / "sample.cpp").write_text(
            "int sample() { return 2; }\n", encoding="utf-8"
        )
        self.july = self._commit("july source", "2026-07-01T00:00:00+00:00")

        (self.repo / "src" / "after.cpp").write_text(
            "int after() { return 3; }\n", encoding="utf-8"
        )
        self.after = self._commit("outside window", "2026-11-01T00:00:00+00:00")

    def _commit(self, message, stamp, *, allow_empty=False):
        if not allow_empty:
            git(self.repo, "add", "-A")
        args = ["commit", "-q", "-m", message]
        if allow_empty:
            args.append("--allow-empty")
        git(self.repo, *args, env=self._commit_env(stamp))
        return git(self.repo, "rev-parse", "HEAD")

    def _commit_env(self, stamp):
        return {
            **os.environ,
            "GIT_AUTHOR_NAME": "MVP CI",
            "GIT_AUTHOR_EMAIL": "mvp@example.invalid",
            "GIT_COMMITTER_NAME": "MVP CI",
            "GIT_COMMITTER_EMAIL": "mvp@example.invalid",
            "GIT_AUTHOR_DATE": stamp,
            "GIT_COMMITTER_DATE": stamp,
        }

    def _window(self, **overrides):
        values = {
            "start": "2026-04-01T00:00:00+00:00",
            "end": "2026-10-01T00:00:00+00:00",
            "timezone": "UTC",
        }
        values.update(overrides)
        return select_window(
            self.repo,
            values.pop("branch", "HEAD"),
            values.pop("start"),
            values.pop("end"),
            values.pop("timezone"),
            **values,
        )

    def _run(self, out_name="output", *, max_commits=5000, scan=None, argv=None):
        target = self.root / out_name
        kwargs = {}
        if scan is not None:
            kwargs["side_effect"] = scan
        with patch("src.ohscanner.halfyear.run_fixed_commit_scan", **kwargs):
            return run_halfyear_candidate_mvp(
                repo_dir=self.repo,
                repository="fixture/halfyear-mvp",
                branch="HEAD",
                start="2026-04-01T00:00:00+00:00",
                end="2026-10-01T00:00:00+00:00",
                timezone="UTC",
                detector_ids=(self.detector_id,),
                out_dir=target,
                max_commits=max_commits,
                argv=argv,
            )

    def _identity(self, path, revision):
        oid = git(self.repo, "rev-parse", f"{revision}:{path}")
        data = git_bytes(self.repo, "cat-file", "blob", oid)
        return oid, hashlib.sha256(data).hexdigest()

    def _fake_scan(self, behavior):
        def scan(repo_dir, repository, commit, includes, detector_ids,
                 json_out, md_out, **kwargs):
            action = behavior.get(commit, {"kind": "complete"})
            if action["kind"] == "raise":
                raise ValueError(action["message"])
            identities = {
                path: self._identity(path, commit) for path in includes
            }
            snapshot = hashlib.sha256(
                (commit + "|" + "|".join(includes)).encode("utf-8")
            ).hexdigest()
            diagnostics = []
            if action.get("candidate"):
                path = includes[0]
                oid, source_sha = identities[path]
                diagnostic_id = self.detector_id + ":fixture"
                binding = {
                    "repository": repository,
                    "commit": commit,
                    "snapshot_sha256": snapshot,
                    "profile_id": "light-ast",
                    "detector_id": self.detector_id,
                    "detector_version": "0.5.0",
                    "rule_id": "fixture-rule",
                    "rule_version": "fixture-rule-v1",
                    "file": path,
                    "source_blob_oid": oid,
                    "source_sha256": source_sha,
                    "byte_start": 0,
                    "byte_end": 1,
                }
                diagnostics.append({
                    "diagnostic_id": diagnostic_id,
                    "provider": self.detector_id,
                    "evidence_type": "syntax",
                    "file": path,
                    "line": 1,
                    "column": 1,
                    "rule_id": "fixture-rule",
                    "severity": "unassessed",
                    "message": "fixture candidate",
                    "candidate_cwe": None,
                    "confidence": "unassessed",
                    "symbol": "fixture",
                    "source_sha256": source_sha,
                    "finding_identity": {
                        "observation": {
                            "rule_version": "fixture-rule-v1",
                            "source_blob_oid": oid,
                            "source_sha256": source_sha,
                            "byte_start": 0,
                            "byte_end": 1,
                            "identity_quality": "partial",
                        },
                        "source_binding": binding,
                    },
                    "source_binding": "bound",
                })
            coverage_status = action.get("coverage", "complete")
            if coverage_status == "complete":
                analyzed = list(includes)
                partial = []
                not_analyzed = []
            elif coverage_status == "partial":
                analyzed = list(includes)
                partial = list(includes)
                not_analyzed = []
            else:
                analyzed = []
                partial = []
                not_analyzed = list(includes)
            run_status = action.get(
                "run_status",
                "blocked" if coverage_status == "blocked" else
                "failed" if coverage_status == "failed" else "completed",
            )
            report = {
                "schema_version": 1,
                "repository": repository,
                "target_id": "current-component:" + repository,
                "commit": commit,
                "git_tree": git(self.repo, "rev-parse", commit + "^{tree}"),
                "snapshot_sha256": snapshot,
                "profile_id": "light-ast",
                "provenance": "local_git_objects",
                "status": (
                    "completed" if coverage_status == "complete"
                    else "completed_with_limitations"
                ),
                "scope": {
                    "selected_source_files": len(includes),
                    "selected_source_bytes": 10,
                },
                "limitations": ["fixture limitation"],
                "detector_runs": [{
                    "schema_version": 2,
                    "run_id": commit + ":" + self.detector_id,
                    "tool": self.detector_id,
                    "tool_version": "0.5.0",
                    "target_id": "current-component:" + repository,
                    "commit": commit,
                    "status": run_status,
                    "diagnostic_count": len(diagnostics),
                    "diagnostics": diagnostics,
                    "limitations": [],
                }],
                "detector_coverage": {"detectors": {
                    self.detector_id: {
                        "status": coverage_status,
                        "applicable_files": len(includes),
                        "analyzed_files": analyzed,
                        "partially_inspected_files": partial,
                        "not_analyzed_files": not_analyzed,
                        "coverage_counts": {
                            "complete": len(analyzed),
                            "partial": len(partial),
                            "not_analyzed": len(not_analyzed),
                            "failed": 0,
                        },
                        "source_sha256": {
                            path: identities[path][1] for path in includes
                        },
                        "unexamined": [],
                        "evidence_obligations": [{
                            "diagnostic_id": self.detector_id + ":fixture",
                            "obligations": [{
                                "kind": "reachability",
                                "description": "entry boundary unknown",
                                "status": "unknown",
                            }],
                        }] if diagnostics else [],
                    },
                }},
            }
            json_out.write_text(json.dumps(report), encoding="utf-8")
            md_out.write_text("fixture\n", encoding="utf-8")
            return report
        return scan

    def test_select_window_uses_committer_time_and_parent_span(self):
        selection = self._window()
        self.assertEqual(selection["selected_commits"], [self.july, self.june, self.may])
        self.assertEqual(selection["endpoint"], self.july)
        self.assertEqual(selection["oldest_selected"], self.may)
        self.assertEqual(selection["baseline"], self.initial)
        self.assertEqual(selection["topology"], "first-parent")
        self.assertEqual(selection["boundary"], "[start,end)")
        self.assertNotIn(self.after, selection["selected_commits"])

    def test_window_boundaries_are_half_open_and_naive_values_use_timezone(self):
        start_boundary = self._commit(
            "start boundary", "2026-04-01T00:00:00+00:00", allow_empty=True,
        )
        selection = self._window(
            start="2026-04-01T00:00:00",
            end="2026-11-01T00:00:00",
        )
        self.assertIn(start_boundary, selection["selected_commits"])
        self.assertNotIn(self.after, selection["selected_commits"])
        meta = {item["commit"]: item for item in selection["selected_commit_meta"]}
        self.assertEqual(
            datetime.fromisoformat(meta[start_boundary]["committer_time"]),
            datetime(2026, 4, 1, tzinfo=timezone.utc),
        )

    def test_first_parent_selection_uses_explicit_ref_and_excludes_second_parent(self):
        tree = git(self.repo, "rev-parse", self.july + "^{tree}")
        side = git(
            self.repo, "commit-tree", tree, "-p", self.july,
            "-m", "second parent source", env=self._commit_env(
                "2026-08-01T00:00:00+00:00"
            ),
        )
        merge = git(
            self.repo, "commit-tree", tree, "-p", self.july, "-p", side,
            "-m", "first parent merge", env=self._commit_env(
                "2026-08-02T00:00:00+00:00"
            ),
        )
        git(self.repo, "update-ref", "refs/heads/window-ref", merge)
        selection = self._window(branch="refs/heads/window-ref")
        self.assertIn(merge, selection["selected_commits"])
        self.assertNotIn(side, selection["selected_commits"])
        self.assertEqual(selection["branch"], "refs/heads/window-ref")

    def test_deleted_only_empty_commit_and_no_source_change_are_not_zero_candidates(self):
        deleted = self.repo / "src" / "deleted.cpp"
        deleted.write_text("int deleted() { return 4; }\n", encoding="utf-8")
        added = self._commit("add deleted source", "2026-08-01T00:00:00+00:00")
        deleted.unlink()
        removed = self._commit("delete source", "2026-08-02T00:00:00+00:00")
        empty = self._commit(
            "empty", "2026-08-03T00:00:00+00:00", allow_empty=True,
        )
        report = self._run(
            "deleted-output",
            scan=self._fake_scan({}),
        )
        entries = {item["commit"]: item for item in report["commits"]}
        self.assertEqual(entries[removed]["change_status"], "deleted_only_source_changes")
        self.assertEqual(entries[removed]["deleted_changed_source_paths"], ["src/deleted.cpp"])
        self.assertIsNone(entries[removed]["candidate_count"])
        self.assertEqual(entries[removed]["execution_status"], "unexecuted")
        deleted_row = entries[removed]["source_manifest"][0]
        self.assertFalse(deleted_row["present_in_commit"])
        self.assertEqual(deleted_row["binding_revision"], added)
        self.assertEqual(deleted_row["binding_status"], "bound")
        self.assertEqual(entries[empty]["change_status"], "no_source_changes")
        self.assertIsNone(entries[empty]["candidate_count"])
        self.assertEqual(entries[self.june]["change_status"], "no_source_changes")
        self.assertEqual(report["totals"]["deleted_only_source_change_commits"], 1)
        self.assertEqual(report["totals"]["no_source_change_commits"], 2)

    def test_missing_git_object_is_blocked_unknown_not_zero(self):
        scan = self._fake_scan({
            self.may: {
                "kind": "raise",
                "message": "missing_local_git_object: unavailable blob",
            },
            self.july: {
                "kind": "raise",
                "message": "missing_local_git_object: unavailable blob",
            },
        })
        report = self._run("missing-output", scan=scan)
        entries = {item["commit"]: item for item in report["commits"]}
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["totals"]["blocked_commits"], 2)
        self.assertEqual(entries[self.may]["failure_kind"], "missing_git_object")
        self.assertIsNone(entries[self.may]["candidate_count"])
        self.assertEqual(entries[self.may]["candidate_count_status"], "unknown_blocked")
        self.assertEqual(report["candidate_status"], "candidate/unassessed")

    def test_detector_blocked_keeps_other_complete_zero_and_never_calls_it_safe(self):
        scan = self._fake_scan({
            self.may: {"kind": "normal", "coverage": "blocked"},
            self.july: {"kind": "normal", "coverage": "complete"},
        })
        report = self._run("blocked-output", scan=scan)
        entries = {item["commit"]: item for item in report["commits"]}
        self.assertEqual(entries[self.may]["coverage_status"], "blocked")
        self.assertIsNone(entries[self.may]["candidate_count"])
        self.assertEqual(entries[self.may]["reported_candidate_observations"], 0)
        self.assertEqual(entries[self.july]["candidate_count"], 0)
        self.assertEqual(report["totals"]["detector_blocked_commits"], 1)
        self.assertNotIn(report["status"], {"safe", "miss", "confirmed", "reportable"})

    def test_partial_coverage_preserves_candidate_but_does_not_publish_zero_count(self):
        scan = self._fake_scan({
            self.may: {
                "kind": "normal", "coverage": "partial", "candidate": True,
            },
            self.july: {"kind": "normal", "coverage": "complete"},
        })
        report = self._run("partial-output", scan=scan)
        entries = {item["commit"]: item for item in report["commits"]}
        self.assertEqual(entries[self.may]["coverage_status"], "partial")
        self.assertIsNone(entries[self.may]["candidate_count"])
        self.assertEqual(entries[self.may]["reported_candidate_observations"], 1)
        self.assertEqual(len(report["candidates"]), 1)
        self.assertEqual(report["candidates"][0]["evidence_level"], "candidate/unassessed")
        self.assertEqual(report["totals"]["partial_coverage_commits"], 1)
        self.assertIn("Candidate count is unknown", entries[self.may]["limitations"][-1])

    def test_failed_coverage_is_recorded_separately_and_is_not_zero(self):
        scan = self._fake_scan({
            self.may: {"kind": "normal", "coverage": "failed"},
            self.july: {"kind": "normal", "coverage": "complete"},
        })
        report = self._run("failed-output", scan=scan)
        entries = {item["commit"]: item for item in report["commits"]}
        self.assertEqual(entries[self.may]["coverage_status"], "failed")
        self.assertIsNone(entries[self.may]["candidate_count"])
        self.assertEqual(entries[self.may]["candidate_count_status"], "failed_unknown")
        self.assertEqual(report["totals"]["failed_coverage_commits"], 1)
        self.assertEqual(report["totals"]["commits_with_unknown_candidate_count"], 2)

    def test_schema_v2_report_manifest_binds_files_and_hashes(self):
        invocation = (
            "python", "-m", "src.cli", "ohscan-halfyear",
            "--repo-dir", str(self.repo),
        )
        report = self._run("report-output", scan=self._fake_scan({}), argv=invocation)
        out = self.root / "report-output"
        json_path = out / "halfyear_candidates.json"
        md_path = out / "halfyear_candidates.md"
        manifest_path = out / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(report["schema_version"], 2)
        self.assertEqual(report["source_binding_schema_version"], 2)
        self.assertEqual(report["detector_diagnostic_schema_version"], 2)
        self.assertEqual(list(report["invocation"]["argv"]), list(invocation))
        self.assertTrue(report["invocation"]["argv_exact"])
        self.assertEqual(
            manifest["report_sha256"],
            hashlib.sha256(json_path.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            manifest["markdown_sha256"],
            hashlib.sha256(md_path.read_bytes()).hexdigest(),
        )
        self.assertIn("halfyear_candidates.json", manifest["files"])
        self.assertIn("commits/" + self.may + ".json", manifest["files"])
        for item in manifest["files"].values():
            path = out / item["path"]
            self.assertEqual(
                item["sha256"], hashlib.sha256(path.read_bytes()).hexdigest(),
            )
        may = next(item for item in report["commits"] if item["commit"] == self.may)
        source = may["source_manifest"][0]
        oid, digest = self._identity(source["path"], self.may)
        self.assertEqual(may["change_status"], "source_changes_present")
        self.assertEqual(source["source_blob_oid"], oid)
        self.assertEqual(source["source_sha256"], digest)
        self.assertEqual(report["detectors"][0]["version"], "0.5.0")

    def test_max_commits_rejects_oversized_selected_window_without_truncation(self):
        with self.assertRaisesRegex(ValueError, "max_commits=2"):
            self._window(max_commits=2)


if __name__ == "__main__":
    unittest.main()
