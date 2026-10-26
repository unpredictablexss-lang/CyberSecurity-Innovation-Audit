from __future__ import annotations

import hashlib
import importlib.util
import csv
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "research/deliveries/cpp/holdout-arkcompiler-ets-frontend-fadba67/prepare_blind_review.py"
FREEZE_SHA256 = hashlib.sha256(
    (ROOT / "research/deliveries/cpp/ark-runtime-c-line-algorithm-freeze-20261018.json").read_bytes()
).hexdigest()
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location("c_line_holdout_prepare", SCRIPT)
assert spec and spec.loader
prepare = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = prepare
spec.loader.exec_module(prepare)


class HoldoutFreezeTests(unittest.TestCase):
    def test_accepts_exact_algorithm_and_support_file_hashes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "src" / "matcher.py"
            source.parent.mkdir()
            source.write_text("frozen\n", encoding="utf-8")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            freeze = {
                "detector_version": "0.3.8",
                "implementation_sha256": {"src/matcher.py": digest},
                "implementation_support_sha256": {},
            }
            manifest = {
                "algorithm_freeze": "research/deliveries/cpp/ark-runtime-c-line-algorithm-freeze-20261018.json",
                "algorithm_freeze_sha256": FREEZE_SHA256,
                "current_binding_version": "0.3.8",
            }
            self.assertEqual(prepare.freeze_mismatches(freeze, manifest, root=root), [])

    def test_rejects_matcher_drift_and_version_mismatch(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "src" / "matcher.py"
            source.parent.mkdir()
            source.write_text("changed\n", encoding="utf-8")
            freeze = {
                "detector_version": "0.3.8",
                "implementation_sha256": {"src/matcher.py": "0" * 64},
                "implementation_support_sha256": {},
            }
            manifest = {
                "algorithm_freeze": "research/deliveries/cpp/ark-runtime-c-line-algorithm-freeze-20261018.json",
                "algorithm_freeze_sha256": FREEZE_SHA256,
                "current_binding_version": "0.3.7",
            }
            self.assertEqual(
                prepare.freeze_mismatches(freeze, manifest, root=root),
                ["holdout binding version differs from the frozen detector version"],
            )
            manifest["current_binding_version"] = "0.3.8"
            self.assertEqual(
                prepare.freeze_mismatches(freeze, manifest, root=root),
                ["sha256:src/matcher.py"],
            )

    def test_generated_packet_is_cross_file_pinned_and_unlabeled(self):
        holdout = ROOT / "research/deliveries/cpp/holdout-arkcompiler-ets-frontend-fadba67"
        manifest = json.loads((holdout / "blind_manifest.json").read_text(encoding="utf-8"))
        census = json.loads((holdout / "component_census.json").read_text(encoding="utf-8"))
        with (holdout / "reviewer_labels.csv").open(encoding="utf-8", newline="") as handle:
            labels = list(csv.DictReader(handle))
        packet = (holdout / "blind_packet.md").read_text(encoding="utf-8")
        self.assertEqual(prepare.packet_issues(manifest, census, labels, packet), [])

        labels[0]["evidence_label"] = "candidate"
        self.assertIn("review_labels_are_not_blank",
                      prepare.packet_issues(manifest, census, labels, packet))


if __name__ == "__main__":
    unittest.main()
