"""Synthetic fail-closed checks for supplemental source identity summaries."""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "supplemental_source_identity_evidence.py"
SPEC = importlib.util.spec_from_file_location("supplemental_source_identity_evidence", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class SupplementalEvidenceSummaryTests(unittest.TestCase):
    def test_recorded_match_mismatch_and_absent_value_are_distinct(self) -> None:
        self.assertEqual(MODULE.compare_recorded("abc", "abc"), "MATCH")
        self.assertEqual(MODULE.compare_recorded("abc", "def"), "MISMATCH")
        self.assertEqual(MODULE.compare_recorded(None, "def"), "NOT_RECORDED")

    def test_summary_counts_mismatch_and_missing_side_path(self) -> None:
        evidence = [{
            "parent": {"tree_check": "MISMATCH", "files": [{
                "status": "OBJECT_BYTES_RECOMPUTED",
                "checks_against_manifest": {
                    "recorded_git_blob_oid": "MATCH",
                    "recorded_source_sha256": "NOT_RECORDED",
                    "recorded_bytes": "MISMATCH",
                },
            }]},
            "fixed": {"tree_check": "NOT_RECORDED", "files": [{"status": "NOT_PRESENT_IN_THIS_SIDE"}]},
        }]
        summary = MODULE.summarize(evidence, [{"case_id": "synthetic-unanchored"}])
        self.assertEqual(summary["anchored_cases"], 1)
        self.assertEqual(summary["unanchored_cases"], 1)
        self.assertEqual(summary["recorded_identity_checks"], {"MATCH": 1, "NOT_RECORDED": 2, "MISMATCH": 2})
        self.assertEqual(summary["missing_side_paths"], 1)
        self.assertTrue(MODULE.has_verification_failure(summary))

    def test_unrecorded_values_alone_do_not_fail(self) -> None:
        summary = MODULE.summarize([{
            "parent": {"tree_check": "NOT_RECORDED", "files": []},
            "fixed": {"tree_check": "NOT_RECORDED", "files": []},
            "parent_is_ancestor_of_fixed": "PASS",
        }], [])
        self.assertFalse(MODULE.has_verification_failure(summary))

    def test_blocked_objects_trees_and_ancestry_failures_are_counted_and_block(self) -> None:
        mutations = [
            ({"parent": {"status": "BLOCKED_OBJECT_MISSING_OR_WRONG_TYPE", "files": []},
              "fixed": {"status": "OBJECTS_RECOMPUTED", "tree_check": "NOT_RECORDED", "files": []},
              "parent_is_ancestor_of_fixed": "PASS"}, "missing_or_wrong_type_commit_objects"),
            ({"parent": {"status": "OBJECTS_RECOMPUTED", "tree_check": "NOT_RECORDED", "files": []},
              "fixed": {"status": "BLOCKED_TREE_MISSING", "tree_check": "NOT_RECORDED", "files": []},
              "parent_is_ancestor_of_fixed": "PASS"}, "missing_trees"),
            ({"parent": {"status": "OBJECTS_RECOMPUTED", "tree_check": "NOT_RECORDED", "files": []},
              "fixed": {"status": "OBJECTS_RECOMPUTED", "tree_check": "NOT_RECORDED", "files": []},
              "parent_is_ancestor_of_fixed": "FAIL"}, "ancestry_failures"),
            ({"parent": {"status": "OBJECTS_RECOMPUTED", "tree_check": "NOT_RECORDED", "files": []},
              "fixed": {"status": "OBJECTS_RECOMPUTED", "tree_check": "NOT_RECORDED", "files": []},
              "parent_is_ancestor_of_fixed": "BLOCKED_ERROR"}, "ancestry_errors"),
        ]
        for mutation, counter in mutations:
            with self.subTest(counter=counter):
                summary = MODULE.summarize([mutation], [])
                self.assertEqual(summary["blockers"][counter], 1)
                self.assertTrue(MODULE.has_verification_failure(summary))

    def test_missing_commit_side_and_unknown_ancestry_are_blockers(self) -> None:
        summary = MODULE.summarize([{
            "parent": {"status": "UNKNOWN", "files": []},
            "fixed": {"status": "OBJECTS_RECOMPUTED", "tree_check": "NOT_RECORDED", "files": []},
            "parent_is_ancestor_of_fixed": "UNKNOWN",
        }], [])
        self.assertEqual(summary["blockers"]["missing_commit_sides"], 1)
        self.assertEqual(summary["blockers"]["ancestry_unknown"], 1)
        self.assertTrue(MODULE.has_verification_failure(summary))

    def test_builtin_negative_validation(self) -> None:
        MODULE.self_test()


if __name__ == "__main__":
    unittest.main()
