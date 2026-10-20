"""Recall claims require an independently labelled and frozen real holdout."""
import json
import hashlib
from pathlib import Path
import unittest

from src.ohscanner.detectors.interface.families import registry
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector
from src.ohscanner.detectors.interface.models import RULE_VERSION_BY_RULE

MANIFEST = (Path(__file__).parent.parent / "research/evidence/interface/ipc/"
            "high_recall_holdout_20261018/manifest.json")
CURRENT_DECLARATION = (Path(__file__).parent.parent / "research/evidence/interface/ipc/"
                       "current_rule_measurement_20261020.json")


class IpcHoldoutContractTests(unittest.TestCase):
    def test_historical_holdout_snapshot_is_immutable_and_new_rule_is_separately_unmeasured(self):
        # This historical snapshot predates DATA-06. Keep its bytes and declared
        # family set stable; do not retrofit later rules or present synthetic
        # controls as holdout measurements.
        self.assertEqual(hashlib.sha256(MANIFEST.read_bytes()).hexdigest(),
                         "314c97104ba19a0f9dda06359449708728a50c9bf9c7a5f89bb7e95bb3886e0d")
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        rows = {item["family_id"]: item for item in manifest["families"]}

        historical_families = {
            "AUTH-01", "AUTH-02", "AUTH-03", "AUTH-04", "AUTH-05", "CAP-01",
            "DATA-01", "DATA-02", "DATA-03", "DATA-04", "DATA-05", "AUTH-06", "AUTH-07",
        }
        self.assertEqual(set(rows), historical_families)
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

        current = json.loads(CURRENT_DECLARATION.read_text(encoding="utf-8"))
        self.assertEqual(current["detector_id"], IpcInterfaceDetector.detector_id)
        self.assertEqual(current["detector_version"], IpcInterfaceDetector.version)
        self.assertEqual(current["model_version"], IpcInterfaceDetector.model_version)
        self.assertEqual(current["family_id"], "DATA-06")
        current_family = next(item for item in registry() if item.family_id == "DATA-06")
        self.assertEqual(current["rules"], list(current_family.rules))
        self.assertEqual(current["rule_versions"],
                         {rule: RULE_VERSION_BY_RULE[rule] for rule in current_family.rules})
        self.assertEqual(current["measurement_status"], "not_run")
        self.assertEqual(current["holdout_case_ids"], [])


if __name__ == "__main__":
    unittest.main()
