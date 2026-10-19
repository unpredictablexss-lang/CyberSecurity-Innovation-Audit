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
        }], [])
        self.assertFalse(MODULE.has_verification_failure(summary))

    def test_builtin_negative_validation(self) -> None:
        MODULE.self_test()


if __name__ == "__main__":
    unittest.main()
