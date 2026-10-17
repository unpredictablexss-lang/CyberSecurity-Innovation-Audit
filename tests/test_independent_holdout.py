from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from src.ohscanner.holdout import (
    save_json,
    summarize_predictions,
    truth_records,
    verify_freeze,
    write_freeze_files,
)


ROOT = Path(__file__).resolve().parents[1]
HOLDOUT = ROOT / "research/evidence/holdout/independent_20261017"
RUN = HOLDOUT / "run_20261017_single"


class IndependentHoldoutFreezeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads((HOLDOUT / "holdout_manifest.json").read_text(encoding="utf-8"))

    def test_frozen_manifest_has_30_independent_pairs(self):
        verify_freeze(self.manifest)
        self.assertEqual(len(self.manifest["root_causes"]), 30)
        self.assertEqual(len(truth_records(self.manifest)), 60)
        self.assertEqual(len({row["stable_patch_id"] for row in self.manifest["root_causes"]}), 30)
        self.assertEqual(
            hashlib.sha256((HOLDOUT / "holdout_manifest.json").read_bytes()).hexdigest(),
            (HOLDOUT / "FREEZE.sha256").read_text(encoding="utf-8").splitlines()[0].split()[0],
        )

    def test_duplicate_patch_id_is_rejected(self):
        altered = copy.deepcopy(self.manifest)
        altered["root_causes"][1]["stable_patch_id"] = altered["root_causes"][0]["stable_patch_id"]
        with self.assertRaisesRegex(ValueError, "duplicate stable patch ID"):
            verify_freeze(altered)

    def test_unknown_is_never_converted_to_a_miss(self):
        predictions = [
            {"sample_id": row["sample_id"], "prediction": "unknown", "detector_status": "blocked"}
            for row in truth_records(self.manifest)
        ]
        metrics = summarize_predictions(self.manifest, predictions)
        self.assertEqual(metrics["sample_level"]["observed_counts"], {"TP": 0, "FP": 0, "FN": 0, "TN": 0})
        self.assertEqual(metrics["sample_level"]["unable_to_analyze_count"], 60)
        self.assertEqual(metrics["root_cause_level"]["vulnerable_axis_counts"], {"unable_to_analyze": 30})
        self.assertTrue(all(not row["eligible_for_metrics"] for row in metrics["family_metrics"].values()))

    def test_incomplete_family_does_not_publish_metrics(self):
        predictions = []
        for row in truth_records(self.manifest):
            prediction = "detected" if row["sample_id"].endswith(":vulnerable") else "unknown"
            predictions.append({"sample_id": row["sample_id"], "prediction": prediction})
        metrics = summarize_predictions(self.manifest, predictions)
        family = metrics["family_metrics"]["cpp.null_dereference"]
        self.assertFalse(family["eligible_for_metrics"])
        self.assertIsNone(family["precision"])
        self.assertEqual(family["observed_counts"]["TP"], 5)
        self.assertEqual(family["unable_to_analyze_count"], 5)

    def test_writer_hashes_exact_lf_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            written = write_freeze_files(self.manifest, Path(directory))
            payload = Path(written["manifest_path"]).read_bytes()
            self.assertNotIn(b"\r\n", payload)
            self.assertEqual(hashlib.sha256(payload).hexdigest(), written["manifest_sha256"])


class IndependentHoldoutRunTests(unittest.TestCase):
    def test_complete_run_preserves_frozen_detector_outputs(self):
        run_manifest = json.loads((RUN / "run_manifest.json").read_text(encoding="utf-8"))
        for name in ("results.json", "predictions.json", "metrics.json"):
            payload = (RUN / name).read_bytes()
            self.assertNotIn(b"\r\n", payload)
            self.assertEqual(hashlib.sha256(payload).hexdigest(), run_manifest["artifacts"][name])
        self.assertTrue(run_manifest["metrics_recomputed_without_detector_execution"])
        self.assertFalse(run_manifest["aborted_preflight"]["used_for_metrics"])

    def test_saved_json_hash_matches_written_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "value.json"
            digest = save_json(path, {"b": 2, "a": 1})
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
