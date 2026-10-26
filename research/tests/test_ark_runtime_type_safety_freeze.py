from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from research.full_scan_20261018.lanes.c.model import RuntimeTypeModel
from research.full_scan_20261018.lanes.c.detector import ArkRuntimeTypeSafetyDetector
from research.full_scan_20261018.lanes.c.analysis import analyze_unit
from src.ohscanner.contracts import SourceUnit


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
        for relative, expected in manifest.get("implementation_support_sha256", {}).items():
            actual = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
            with self.subTest(file=relative):
                self.assertEqual(actual, expected)

    def test_both_exact_replay_profiles_bind_creator_and_model_sources(self):
        model = RuntimeTypeModel()
        self.assertEqual(len(model.bindings_for_commit(model.source_profiles[0][0])), 40)
        self.assertEqual(len(model.bindings_for_commit(model.source_profiles[1][0])), 40)
        self.assertEqual(model.bindings_for_commit("1" * 40), ())

    def test_only_filter_is_an_active_semantic_caller(self):
        import hashlib
        from src.ohscanner.contracts import SourceUnit
        from research.full_scan_20261018.lanes.c.analysis import analyze_unit
        from research.full_scan_20261018.lanes.c.model import CALLER, OWNER
        model = RuntimeTypeModel()
        self.assertEqual(model.callers, (CALLER,))
        self.assertTrue(all(name.endswith(("::CopyWithin", "::Set", "::With"))
                            for name in model.caller_profiles))
        source = f"void {OWNER}::Set(GateRef glue, GateRef thisValue, GateRef numArgs, Variable* result, Label* exit, Label* slow) {{}}\n"
        unit = SourceUnit("control.cpp", "cpp", source,
                          hashlib.sha256(source.encode()).hexdigest(), "complete")
        result = analyze_unit(unit, model=model)
        self.assertEqual(result.file_outcome, "complete")
        self.assertEqual(result.limitations, ("not_applicable_to_rule",))

    def test_parser_environment_drift_fails_closed_before_analysis(self):
        model = RuntimeTypeModel()
        changed = replace(model, parser_environment=(('tree-sitter', '0.0.0'),))
        source = "void unrelated() {}\n"
        unit = SourceUnit("control.cpp", "cpp", source,
                          hashlib.sha256(source.encode()).hexdigest(), "complete")
        result = analyze_unit(unit, model=changed)
        self.assertEqual(result.status, "limited")
        self.assertEqual(result.file_outcome, "not_analyzed")
        self.assertEqual(result.limitations, ("parser_environment_mismatch",))


if __name__ == "__main__":
    unittest.main()
