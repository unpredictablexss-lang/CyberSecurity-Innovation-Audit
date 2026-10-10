import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from src.benchmark.component import git_oid, tree_oid
from src.benchmark.component_review import REVIEW_FIELDS, build_review_ledger, render_review_markdown


class ComponentReviewTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.snapshot = self.root / "snapshot"
        source = self.snapshot / "source"
        self.files = {
            "base/src/a.cpp": "template <class T> int f(T value) { return value; }\n",
            "base/test/unit.cpp": "HWTEST_F(Suite, Case, TestSize.Level0) { EXPECT_EQ(1, 1); }\n",
        }
        records = []
        for file, text in self.files.items():
            data = text.encode()
            target = source / file
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            records.append(dict(path=file, mode="100644", blob=git_oid("blob", data),
                                sha256=hashlib.sha256(data).hexdigest(),
                                language_scope="cpp"))
        tree = tree_oid(records)
        commit = ("tree " + tree + "\nauthor Tester <t@example.com> 0 +0000\n"
                  "committer Tester <t@example.com> 0 +0000\n\nfixture\n").encode()
        self.manifest = dict(
            experiment_kind="current_component", files=records,
            repository="openharmony/commonlibrary_c_utils", tree=tree,
            commit=git_oid("commit", commit),
            commit_object_b64=base64.b64encode(commit).decode(),
        )
        (self.snapshot / "snapshot.json").write_text(json.dumps(self.manifest))
        self.reports = self.root / "reports"
        self.reports.mkdir()

    def report(self, name, tool="semgrep", run_id="run-1", file="base/src/a.cpp",
               line=1, parsing=None, commit=None, target=None):
        diagnostic = dict(
            diagnostic_id=tool + ":" + file + ":1", provider=tool,
            evidence_type="pattern", file=file, line=line, column=1,
            rule_id="fixture-rule", severity="warning", message="candidate only",
            candidate_cwe=None, confidence="unassessed", symbol=None,
        )
        payload = dict(
            schema_version=1, run_id=run_id, tool=tool, tool_version="1",
            target_id=target or "current-component:openharmony/commonlibrary_c_utils",
            commit=commit or self.manifest["commit"], scope_files=2, scope_loc=2,
            status="completed", elapsed_seconds=1.0, peak_memory_mb=None,
            diagnostic_count=1, diagnostics=[diagnostic], limitations=["fixture"],
            parsing=parsing or [],
        )
        path = self.reports / name
        path.write_text(json.dumps(payload))
        return path

    def test_duplicate_diagnostics_are_retained_with_full_defaults(self):
        first = self.report("one.json")
        second = self.report("two.json", run_id="run-2")
        ledger = build_review_ledger(self.snapshot, [first, second])
        self.assertEqual(len(ledger["review_entries"]), 2)
        self.assertEqual({item["review_status"] for item in ledger["review_entries"]}, {"unassessed"})
        self.assertEqual({item["candidate_status"] for item in ledger["review_entries"]}, {"candidate"})
        self.assertEqual({item["case_status"] for item in ledger["review_entries"]}, {"draft"})
        for entry in ledger["review_entries"]:
            for field, value in REVIEW_FIELDS.items():
                self.assertEqual(entry[field], value)
            self.assertTrue(entry["source_report_path"])
            self.assertEqual(entry["source_report_sha256"],
                             hashlib.sha256(Path(entry["source_report_path"]).read_bytes()).hexdigest())
            self.assertTrue(entry["source_context"])
        self.assertEqual(ledger["validated_vulnerability"], 0)
        self.assertEqual(ledger["counts"]["review_entries_by_tool"], {"semgrep": 2})
        self.assertEqual(ledger["source_reports"][0]["production_review_count"], 1)
        self.assertEqual(ledger["source_reports"][0]["diagnostic_count"], 1)

    def test_evidence_mixing_and_duplicate_report_binding_are_rejected(self):
        first = self.report("one.json")
        mismatched_commit = self.report("commit.json", commit="b" * 40)
        mismatched_target = self.report("target.json", target="historical:sample")
        with self.assertRaisesRegex(ValueError, "commit mismatch"):
            build_review_ledger(self.snapshot, [first, mismatched_commit])
        with self.assertRaisesRegex(ValueError, "target mismatch"):
            build_review_ledger(self.snapshot, [first, mismatched_target])
        with self.assertRaisesRegex(ValueError, "Duplicate normalized report binding"):
            build_review_ledger(self.snapshot, [first, first])

    def test_recorded_report_sha_mismatch_is_rejected(self):
        report = self.report("one.json")
        expected = {str(report.resolve()): "0" * 64}
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            build_review_ledger(self.snapshot, [report], expected)
        expected[str(report.resolve())] = hashlib.sha256(report.read_bytes()).hexdigest()
        self.assertEqual(build_review_ledger(self.snapshot, [report], expected)["counts"]["review_entries"], 1)

    def test_partial_parser_records_keep_candidate_causes(self):
        parsing = [
            dict(file="base/src/a.cpp", status="partial",
                 issues=[dict(kind="error", start_line=1, end_line=1)]),
            dict(file="base/test/unit.cpp", status="partial",
                 issues=[dict(kind="missing", start_line=1, end_line=1)]),
        ]
        report = self.report("ast.json", tool="own_ast", parsing=parsing)
        ledger = build_review_ledger(self.snapshot, [report])
        self.assertEqual(ledger["counts"]["partial_production"], 1)
        self.assertEqual(ledger["counts"]["partial_tests"], 1)
        for item in ledger["partial_parsing"]:
            self.assertEqual(item["parser_status"], "partial")
            self.assertEqual(item["cause_status"], "candidate_cause")
            self.assertEqual(item["source_syntax_status"], "unknown")
            self.assertEqual(item["real_syntax_issue_status"], "unknown")
        self.assertIn("template_or_uninstantiated", ledger["partial_parsing"][0]["possible_causes"])
        self.assertIn("real_syntax_issue", ledger["partial_parsing"][0]["possible_causes"])
        self.assertIn("macro_expansion", ledger["partial_parsing"][1]["possible_causes"])
        self.assertIn("missing_dependency_or_preprocessor_branch",
                      ledger["partial_parsing"][1]["possible_causes"])

    def test_markdown_contains_every_entry_and_evidence_binding(self):
        first = self.report("one.json")
        second = self.report("two.json", tool="cppcheck", run_id="run-2")
        ledger = build_review_ledger(self.snapshot, [first, second])
        markdown = render_review_markdown(ledger)
        for entry in ledger["review_entries"]:
            self.assertIn(entry["review_entry_id"], markdown)
            self.assertIn(entry["source_report_sha256"], markdown)
            self.assertIn(entry["source_location"]["file"], markdown)
            self.assertIn(entry["source_report_path"], markdown)
            self.assertIn(entry["source_context"][0]["code"], markdown)
        self.assertIn("candidate / unassessed / draft", markdown)

    def test_out_of_snapshot_diagnostic_is_rejected(self):
        report = self.report("outside.json", file="outside.cpp")
        with self.assertRaisesRegex(ValueError, "outside pinned snapshot"):
            build_review_ledger(self.snapshot, [report])
