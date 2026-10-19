import importlib.util
import os
import sys
from pathlib import Path
import unittest

from src.ohscanner.detectors.ark_runtime.analysis import analyze_unit
from .support import case, unit, wrap, PREFIX


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "research/experiments/ark_runtime/c13_ark_real_replay_20261019/c13_real_replay.py"
spec = importlib.util.spec_from_file_location("c13_real_replay", SCRIPT)
c13 = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = c13
spec.loader.exec_module(c13)


class C13RealReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = Path(os.environ.get(
            "OHSCANNER_C13_ARK_REPO",
            r"E:\网安\_oh_targets\arkcompiler_ets_runtime",
        ))

    def test_five_controls_keep_positive_hit_and_fixed_safe_unrelated_unknown(self):
        controls = (
            ("positive", case("C03"), "candidate"),
            ("fixed", case("C04"), "matched"),
            ("safe", case("C04"), "matched"),
            ("unrelated", unit(wrap("GateRef local = Input();")), ""),
            ("unknown", unit(wrap(PREFIX + "StoreTypedArrayElement(glue, output, inputTag);")), "unknown"),
        )
        observed = {}
        for name, source, expected in controls:
            result = analyze_unit(source)
            kinds = [item.kind for item in result.observations]
            observed[name] = kinds
            if expected:
                self.assertIn(expected, kinds, (name, kinds, result.limitations))
            else:
                self.assertNotIn("candidate", kinds, (name, kinds, result.limitations))
        self.assertEqual(observed["positive"], ["candidate"])
        self.assertEqual(observed["fixed"], ["matched"])
        self.assertEqual(observed["safe"], ["matched"])
        self.assertNotIn("candidate", observed["unrelated"])
        self.assertEqual(observed["unknown"], ["unknown"])

    def test_manifest_is_source_bound_and_missing_blob_fails_closed(self):
        if not self.repo.exists():
            self.skipTest("pinned Ark Runtime Git store unavailable")
        manifest = c13.inventory(self.repo)
        self.assertTrue(manifest["fail_closed"])
        self.assertEqual(manifest["source_audit"]["status"], "verified")
        pair = manifest["cases"][0]
        self.assertEqual(pair["parent"]["status"], "verified")
        self.assertEqual(pair["fixed"]["status"], "verified")
        bad = dict(c13.PARENT, blob="0" * 40)
        with self.assertRaises(c13.C13ObjectError):
            c13.verify_source(self.repo, bad)

    def test_production_cli_replay_is_retained_and_partial_is_not_safe(self):
        if not self.repo.exists():
            self.skipTest("pinned Ark Runtime Git store unavailable")
        out = SCRIPT.parent / "reports-test"
        result = c13.replay(self.repo, out)
        self.assertEqual(result["case_id"], "IBS5YG")
        self.assertEqual(result["manifest"]["cases"][0]["parent"]["status"], "verified")
        self.assertEqual(result["manifest"]["cases"][0]["fixed"]["status"], "verified")
        self.assertIn("parent_same_root_count", result["observed_shape"])
        self.assertIn("fixed_same_root_count", result["observed_shape"])
        # Current production entry point is retained even when its bounded
        # semantic model is partial; zero on a blocked side is not a safe pass.
        self.assertIn(result["status"], {"blocked_partial_unknown", "replayed"})
        self.assertTrue((out / "ibs5yg-parent.json").exists())
        self.assertTrue((out / "ibs5yg-fixed.json").exists())


if __name__ == "__main__":
    unittest.main()

