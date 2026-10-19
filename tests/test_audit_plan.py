from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from src.ohscanner.fixture import snapshot_digest
from src.workbench.sources import SourceFile, SourceManifest
from src.workbench.planning import plan_audit, metadata_from_detectors


def file(path="a.cpp", language="cpp", parse_status="complete"):
    return SourceFile(path, language, sha256(path.encode()).hexdigest(), parse_status, "f" * 40)


def manifest(files=None, **changes):
    files = tuple([file()] if files is None else files)
    values = dict(repository="test/component", commit="a" * 40, git_tree="b" * 40,
                  snapshot_sha256=snapshot_digest(sorted(files, key=lambda f: f.path)),
                  files=files, available_facts=("ast",), provenance="context_snapshot_checked")
    values.update(changes)
    return SourceManifest(**values)


def metadata(ident="ohscanner.test.cpp", languages=None, **changes):
    row = dict(id=ident, version="1.0", kind="research_candidate",
               supported_languages=["cpp"] if languages is None else languages,
               required_facts=["ast"])
    row.update(changes)
    return row


class AuditPlanTests(unittest.TestCase):
    def test_automatic_matching_uses_supplied_catalog_not_static_ids(self):
        plan = plan_audit(manifest(), [metadata(ident="ohscanner.future.reviewed")])
        self.assertEqual(plan["suggested_detector_ids"], ["ohscanner.future.reviewed"])
        self.assertEqual(plan["status"], "ready")
        self.assertEqual(plan["detectors"][0]["execution_status"], "not_run")
        self.assertEqual(plan["security_assessment"], "unknown")
        self.assertNotIn("candidate_count", plan)

    def test_mixed_languages_and_unknown_language_are_visible(self):
        source = manifest([file(), file("b.c", "c"), file("c.js", "js", "not_run"), file("d.rs", "rust", "not_run")])
        plan = plan_audit(source, [metadata(), metadata("ohscanner.test.c", ["c"])])
        self.assertEqual(plan["languages"], {"c": 1, "cpp": 1, "js": 1, "rust": 1})
        self.assertEqual([x["file"] for x in plan["files_without_planned_detector"]], ["c.js", "d.rs"])
        self.assertEqual(plan["status"], "ready_with_limitations")

    def test_empty_inventory_is_empty_scope_never_safe(self):
        plan = plan_audit(manifest([]), [metadata()])
        self.assertEqual(plan["status"], "empty_scope")
        self.assertEqual(plan["suggested_detector_ids"], [])
        self.assertEqual(plan["security_assessment"], "unknown")

    def test_unclassified_only_scope_is_blocked_not_empty(self):
        plan = plan_audit(manifest([], unclassified_entries=2), [metadata()])
        self.assertEqual(plan["status"], "blocked")
        self.assertIn({"reason": "unclassified_or_non_source_entries", "count": 2}, plan["needs_review"])

    def test_explicit_inapplicable_selection_does_not_enable_other_detector(self):
        plan = plan_audit(manifest(), [metadata(), metadata("ohscanner.test.js", ["js"])], selected_detector_ids=["ohscanner.test.js"])
        self.assertEqual(plan["suggested_detector_ids"], [])
        self.assertEqual([x["reason_codes"] for x in plan["detectors"]], [["not_selected"], ["no_matching_language"]])
        self.assertEqual(plan["status"], "blocked")

    def test_unknown_and_empty_manual_selection_are_not_automatic(self):
        for chosen, reason in [([], "explicit_empty_selection"), (["ohscanner.unknown"], "unknown_selected_detector")]:
            with self.subTest(chosen=chosen):
                plan = plan_audit(manifest(), [metadata()], selected_detector_ids=chosen)
                self.assertEqual(plan["suggested_detector_ids"], [])
                self.assertIn(reason, [x["reason"] for x in plan["needs_review"]])

    def test_no_catalog_no_applicable_rule_remains_unknown(self):
        for rows in [[], [metadata(languages=["js"])]]:
            plan = plan_audit(manifest(), rows)
            self.assertEqual(plan["status"], "blocked")
            self.assertEqual(plan["security_assessment"], "unknown")

    def test_incomplete_metadata_never_silently_schedules(self):
        for field in ["version", "supported_languages", "kind"]:
            row = metadata(); del row[field]
            with self.subTest(field=field):
                plan = plan_audit(manifest(), [row])
                self.assertEqual(plan["suggested_detector_ids"], [])
                self.assertEqual(plan["detectors"][0]["decision"], "blocked")
        plan = plan_audit(manifest(), [{"version": "1"}, None])
        self.assertEqual(sum(x["reason"] == "missing_detector_id" for x in plan["needs_review"]), 2)

    def test_missing_facts_block_but_missing_fact_declaration_is_unknown(self):
        plan = plan_audit(manifest(available_facts=()), [metadata()])
        self.assertEqual(plan["detectors"][0]["missing_facts"], ["ast"])
        self.assertEqual(plan["suggested_detector_ids"], [])
        row = metadata(); del row["required_facts"]
        plan = plan_audit(manifest(), [row])
        self.assertEqual(plan["detectors"][0]["prerequisite_status"], "unknown")
        self.assertEqual(plan["status"], "ready_with_limitations")

    def test_partial_failed_and_not_run_are_not_promoted_to_analyzed(self):
        plan = plan_audit(manifest([file("a.cpp", parse_status="partial"), file("b.cpp", parse_status="failed"), file("c.cpp", parse_status="not_run")]), [metadata()])
        self.assertEqual(len(plan["parse_limitations"]), 3)
        self.assertEqual(plan["status"], "ready_with_limitations")
        self.assertEqual(plan["detectors"][0]["reason_codes"], ["language_match_attempt"])
        self.assertNotIn("analyzed_files", plan["detectors"][0])

    def test_examples_and_unrecognized_kinds_are_not_automatically_run(self):
        for kind in ["example", "production_but_unreviewed"]:
            self.assertEqual(plan_audit(manifest(), [metadata(kind=kind)])["suggested_detector_ids"], [])

    def test_order_invariance_and_no_input_mutation(self):
        rows = [metadata("ohscanner.z", ["c", "cpp"]), metadata("ohscanner.a")]
        original = deepcopy(rows)
        a = plan_audit(manifest([file(), file("b.c", "c")]), rows)
        rows.reverse();rows[1]["supported_languages"].reverse()
        b = plan_audit(manifest([file("b.c", "c"), file()]), rows)
        self.assertEqual(a, b)
        rows.reverse();rows[0]["supported_languages"].reverse()
        self.assertEqual(rows, original)

    def test_version_source_scope_and_fact_changes_invalidate_plan_digest(self):
        base = plan_audit(manifest(), [metadata()])["plan_sha256"]
        variations = [plan_audit(manifest(commit="c" * 40), [metadata()]),
                      plan_audit(manifest(git_tree="d" * 40), [metadata()]),
                      plan_audit(manifest(), [metadata(version="2")]),
                      plan_audit(manifest(include_paths=("a.cpp",)), [metadata()]),
                      plan_audit(manifest(available_facts=()), [metadata()]),
                      plan_audit(manifest([replace(file(), sha256="e" * 64)]), [metadata()])]
        self.assertTrue(all(p["plan_sha256"] != base for p in variations))

    def test_invalid_bindings_and_selections_fail_closed(self):
        for values in [dict(commit="main"), dict(snapshot_sha256="f" * 64), dict(include_paths=("other",)), dict(skipped_entries=-1), dict(files=(file(), file()))]:
            with self.subTest(values=values), self.assertRaises(ValueError):
                manifest(**values)
        for selection in [["x", "x"], "ohscanner.test.cpp"]:
            with self.assertRaises(ValueError):plan_audit(manifest(), [metadata()], selected_detector_ids=selection)
        with self.assertRaises(ValueError):plan_audit(manifest(), [metadata(), metadata()])

    def test_pure_planning_does_not_call_subprocess_network_or_write_files(self):
        source = manifest(); rows = [metadata()]
        with patch("subprocess.run", side_effect=AssertionError("subprocess")), patch("socket.socket", side_effect=AssertionError("network")), patch("builtins.open", side_effect=AssertionError("file write")):
            self.assertEqual(plan_audit(source, rows)["status"], "ready")

    def test_caller_supplied_binding_keeps_provenance_review(self):
        plan = plan_audit(manifest(provenance="caller_supplied"), [metadata()])
        self.assertEqual(plan["status"], "ready_with_limitations")
        self.assertIn({"reason": "source_binding_not_independently_verified"}, plan["needs_review"])

    def test_metadata_enrichment_never_calls_detector_and_checks_identity(self):
        detector = SimpleNamespace(detector_id="ohscanner.test.cpp", version="1.0", supported_languages=("cpp",), required_facts=("ast",), detect=lambda *_: self.fail("detector executed"))
        row = metadata();del row["required_facts"]
        self.assertEqual(metadata_from_detectors([row], [detector])[0]["required_facts"], ["ast"])
        for change in [dict(version="other"), dict(supported_languages=["c"]), dict(required_facts=["cfg"])]:
            with self.assertRaises(ValueError):metadata_from_detectors([{**row, **change}], [detector])
        with self.assertRaises(ValueError):metadata_from_detectors([row], [detector, detector])

    def test_invalid_facts_are_unknown_and_missing_blob_identity_is_exposed(self):
        plan = plan_audit(manifest(), [metadata(required_facts=None)])
        self.assertEqual(plan["detectors"][0]["prerequisite_status"], "unknown")
        self.assertEqual(plan["suggested_detector_ids"], [])
        plan = plan_audit(manifest([replace(file(), blob_oid=None)]), [metadata()])
        self.assertIn({"reason": "missing_blob_identities", "count": 1}, plan["needs_review"])
        self.assertEqual(plan["status"], "ready_with_limitations")

    def test_invalid_metadata_order_is_stable_and_content_is_bound(self):
        a = plan_audit(manifest(), [metadata(), None, {"extra": "first"}])
        b = plan_audit(manifest(), [{"extra": "first"}, None, metadata()])
        c = plan_audit(manifest(), [metadata(), None, {"extra": "changed"}])
        self.assertEqual(a, b)
        self.assertNotEqual(a["metadata_sha256"], c["metadata_sha256"])
