from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from research.tests.a_null_03_unsafe_memory_review.validate_review_manifest import validate_manifest


class ReviewManifestValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest_path = (
            Path(__file__).resolve().parents[2]
            / "evidence"
            / "cpp"
            / "a_unsafe_memory_review_20261018"
            / "sampling_manifest.json"
        )
        cls.pinned_manifest = json.loads(cls.manifest_path.read_text(encoding="utf-8"))

    def test_current_provisional_manifest_is_valid_without_relabeling_population(self):
        validate_manifest(self.pinned_manifest)
        self.assertEqual(self.pinned_manifest["expected_population"], 8994)
        self.assertEqual(self.pinned_manifest["observed_population"], 9323)
        self.assertTrue(self.pinned_manifest["provisional_frame"])

    def test_raw_observation_count_cannot_drop_rows(self):
        manifest = copy.deepcopy(self.pinned_manifest)
        manifest["report_count_dimensions"]["raw_observation_rows"]["count"] -= 1
        with self.assertRaisesRegex(ValueError, "raw observation dimension"):
            validate_manifest(manifest)

    def test_unknown_root_cause_requires_null_and_reason(self):
        manifest = copy.deepcopy(self.pinned_manifest)
        roots = manifest["report_count_dimensions"]["within_repository_root_cause_clusters"]
        roots["count"] = 0
        with self.assertRaisesRegex(ValueError, "must be null with a reason"):
            validate_manifest(manifest)

    def test_human_review_counts_must_reconcile_to_sample(self):
        manifest = copy.deepcopy(self.pinned_manifest)
        manifest["report_count_dimensions"]["human_review_outcomes"]["pending"] -= 1
        with self.assertRaisesRegex(ValueError, "reconcile to sample_size"):
            validate_manifest(manifest)

    def test_cross_repository_cluster_requires_at_least_two_rows_per_cluster(self):
        manifest = copy.deepcopy(self.pinned_manifest)
        cross = manifest["report_count_dimensions"]["cross_repository_identical_source_clusters"]
        cross["count"] = 1
        cross["rows_in_those_clusters"] = 1
        with self.assertRaisesRegex(ValueError, "at least two repositories"):
            validate_manifest(manifest)

    def test_unknown_disposition_names_are_rejected(self):
        manifest = copy.deepcopy(self.pinned_manifest)
        human = manifest["report_count_dimensions"]["human_review_outcomes"]
        human["disposition_counts"] = {"probably_true": 0}
        with self.assertRaisesRegex(ValueError, "known labels"):
            validate_manifest(manifest)

    def test_v2_requires_recomputable_cross_repository_cluster_evidence(self):
        manifest = copy.deepcopy(self.pinned_manifest)
        manifest["schema_version"] = "ohscanner.a-unsafe-memory-stratified-review-v2"
        cross = manifest["report_count_dimensions"]["cross_repository_identical_source_clusters"]
        cross["clusters"] = []
        validate_manifest(manifest)

        cross["count"] = 1
        cross["rows_in_those_clusters"] = 2
        cross["clusters"] = [{
            "rule_id": "rule-a",
            "source_sha256": "a" * 64,
            "repositories": ["org/a", "org/b"],
            "raw_observation_rows": 2,
        }]
        validate_manifest(manifest)

        cross["clusters"][0]["repositories"] = ["org/a", "org/a"]
        with self.assertRaisesRegex(ValueError, "repositories must be unique"):
            validate_manifest(manifest)


if __name__ == "__main__":
    unittest.main()
