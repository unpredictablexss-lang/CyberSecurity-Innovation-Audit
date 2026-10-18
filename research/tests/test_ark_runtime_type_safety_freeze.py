from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from research.full_scan_20261018.lanes.c.model import RuntimeTypeModel
from research.full_scan_20261018.lanes.c.detector import ArkRuntimeTypeSafetyDetector


FREEZE = ROOT / "research/deliveries/cpp/ark-runtime-c-line-algorithm-freeze-20261018.json"


class AlgorithmFreezeTests(unittest.TestCase):
    def test_implementation_and_model_match_frozen_digests(self):
        manifest = json.loads(FREEZE.read_text(encoding="utf-8"))
        self.assertEqual(manifest["detector_version"], RuntimeTypeModel().version)
        self.assertEqual(manifest["detector_version"], ArkRuntimeTypeSafetyDetector.version)
        self.assertEqual(ArkRuntimeTypeSafetyDetector().model_version, RuntimeTypeModel().version)
        self.assertEqual(manifest["model_sha256"], RuntimeTypeModel().digest)
        for relative, expected in manifest["implementation_sha256"].items():
            actual = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
            with self.subTest(file=relative):
                self.assertEqual(actual, expected)

    def test_both_exact_replay_profiles_bind_creator_and_model_sources(self):
        model = RuntimeTypeModel()
        self.assertEqual(len(model.bindings_for_commit(model.source_profiles[0][0])), 30)
        self.assertEqual(len(model.bindings_for_commit(model.source_profiles[1][0])), 30)
        self.assertEqual(model.bindings_for_commit("1" * 40), ())


if __name__ == "__main__":
    unittest.main()
