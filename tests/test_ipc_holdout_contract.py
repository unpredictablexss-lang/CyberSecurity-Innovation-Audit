"""Recall claims require an independently labelled and frozen real holdout."""
import json
from pathlib import Path
import unittest

from src.ohscanner.detectors.interface.families import registry
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector

MANIFEST = (Path(__file__).parent.parent / "research/evidence/interface/ipc/"
            "high_recall_holdout_20261018/manifest.json")


class IpcHoldoutContractTests(unittest.TestCase):
    def test_every_declared_rule_family_is_explicitly_unmeasured_until_real_holdout_exists(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        declared = {family.family_id: list(family.rules) for family in registry()}
        rows = {item["family_id"]: item for item in manifest["families"]}

        self.assertEqual(set(rows), set(declared))
        self.assertTrue(all(rows[family]["rules"] == rules
                            for family, rules in declared.items()))
        self.assertEqual(manifest["status"], "not_established")
        self.assertFalse(manifest["frozen"])
        # A holdout manifest records the detector that originally produced its
        # unmeasured declaration. Later detector versions must not rewrite history.
        self.assertEqual(manifest["detector_version"], "0.12.1")
        self.assertEqual(manifest["model_version"], "oh-ipc-2026.10-v21")
        self.assertEqual(manifest["detectors"]["ipc"]["version"],
                         manifest["detector_version"])
        self.assertEqual(manifest["detectors"]["ipc"]["model_version"],
                         manifest["model_version"])
        self.assertTrue(all(item["status"] == "unmeasured"
                            and item["independent_positive_count"] == 0
                            and item["holdout_case_ids"] == []
                            for item in rows.values()))
        self.assertFalse(manifest["acceptance_policy"]["unmeasured_family_claim_allowed"])
        self.assertIn("100_percent_true_positive_hits",
                      manifest["acceptance_policy"]["supported_family_requires"])
        # This manifest is an immutable historical snapshot; later code releases must not rewrite its detector version.
        self.assertEqual(manifest["detectors"]["arkts_js"]["version"], "0.3.0")
        expected_arkts = {
            "ohscanner.js.dangerous_eval",
            "ohscanner.js.path_taint",
            "ohscanner.oh.arkts.component_exposure",
            "ohscanner.oh.arkts.webview_bridge",
            "ohscanner.oh.native_bridge",
        }
        arkts_rows = {item["rule_id"]: item for item in manifest["arkts_js_rules"]}
        self.assertEqual(set(arkts_rows), expected_arkts)
        self.assertTrue(all(item["status"] == "unmeasured"
                            and item["independent_positive_count"] == 0
                            and item["holdout_case_ids"] == []
                            for item in arkts_rows.values()))


if __name__ == "__main__":
    unittest.main()
