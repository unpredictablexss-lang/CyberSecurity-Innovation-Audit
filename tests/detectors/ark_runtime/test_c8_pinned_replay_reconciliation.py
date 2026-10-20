import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / "research/experiments/ark_runtime/c8_known_vulnerability_replay_20261019"


def load(name):
    return json.loads((OUT / name).read_text(encoding="utf-8"))


class C8PinnedReplayReconciliationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.audit = load("pinned_artifact_audit.json")
        cls.reconciliation = load("finding_rule_control_reconciliation.json")

    def test_review_objects_are_pinned_but_declared_hash_manifest_is_stale(self):
        acceptance = self.audit["acceptance"]
        self.assertTrue(acceptance["review_object_identity_passed"])
        self.assertFalse(acceptance["declared_hash_manifest_passed"])
        mismatches = [row["path"] for row in self.audit["hash_manifest_checks"] if not row["match"]]
        self.assertEqual(mismatches, [
            "research/experiments/ark-runtime-history-replay-20261018/README.md",
            "docs/项目现状与下一步.md",
        ])

    def test_control_matrix_preserves_all_ac_replay_categories(self):
        rows = {row["category"]: row for row in self.audit["control_matrix"]}
        self.assertEqual(set(rows), {
            "vulnerable_hit", "fixed_miss", "safe_control",
            "unrelated_control", "unknown", "missing_object_fail_closed",
        })
        self.assertFalse(rows["vulnerable_hit"]["satisfied"])
        self.assertFalse(rows["fixed_miss"]["satisfied"])
        self.assertFalse(rows["safe_control"]["satisfied"])
        self.assertTrue(rows["unrelated_control"]["satisfied"])
        self.assertTrue(rows["unknown"]["satisfied"])
        self.assertTrue(rows["missing_object_fail_closed"]["satisfied"])
        self.assertTrue(all(not row["counted_as_detector_pass"] for row in rows.values()))

    def test_all_findings_map_to_rule_and_control_without_pass_or_vulnerability(self):
        self.assertEqual(len(self.reconciliation["entries"]), 12)
        for entry in self.reconciliation["entries"]:
            with self.subTest(entry=entry["entry_id"]):
                self.assertTrue(entry["rule_ids"])
                self.assertTrue(entry["control_ids"])
                self.assertFalse(entry["counted_as_detector_pass"])
                self.assertFalse(entry["validated_vulnerability"])
                self.assertIn(entry["verification_status"], {
                    "blocked_not_replayed", "blocked_unknown", "unknown_limit_only",
                })

    def test_c3_source_hashes_map_to_controls_but_are_not_claimed_replayed(self):
        rows = self.reconciliation["c3_source_hash_reconciliation"]
        self.assertEqual(len(rows), 6)
        self.assertTrue(all(row["hash_match"] for row in rows))
        self.assertTrue(all(row["control_id"] for row in rows))
        self.assertTrue(all(row["pinned_replay_status"] == "not_replayed" for row in rows))
        self.assertTrue(all(not row["counted_as_pass"] for row in rows))

    def test_holdout_packets_have_no_truth_or_metrics(self):
        self.assertEqual(sum(row["reviewer_rows"] for row in self.audit["holdout_packet_review"]), 41)
        self.assertEqual(sum(row["nonempty_evidence_labels"] for row in self.audit["holdout_packet_review"]), 0)
        self.assertFalse(self.audit["acceptance"]["eligible_for_precision_recall"])
        self.assertEqual(self.reconciliation["claim_boundary"]["precision_recall"], None)
        self.assertFalse(self.reconciliation["claim_boundary"]["zero_fp_fn_claim"])


if __name__ == "__main__":
    unittest.main()

