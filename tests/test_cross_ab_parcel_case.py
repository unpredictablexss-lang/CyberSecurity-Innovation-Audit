from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class CrossABParcelCaseTests(unittest.TestCase):
    def test_positive_and_fixed_layers_compose_without_security_overclaim(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "case.json"
            process = subprocess.run(
                [sys.executable, str(ROOT / "scripts/run_cross_ab_parcel_case.py"), "--out", str(out)],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            report = json.loads(out.read_text(encoding="utf-8"))
        cases = {item["category"]: item for item in report["cases"]}
        positive = cases["positive"]
        fixed = cases["fixed"]
        self.assertTrue(any(item["rule_id"] == "ohcpp-memory-bounds-copy-candidate-001" for item in positive["a_bounds_findings"]))
        self.assertTrue(any(item["rule_id"] == "ipc.parcel.copy-range" for item in positive["b_ipc_findings"]))
        self.assertIsNone(positive["facts_v2"][positive["source"]["path"]]["ranges"][0]["maximum"])
        self.assertEqual(fixed["a_bounds_findings"], [])
        self.assertEqual(fixed["b_ipc_findings"], [])
        self.assertEqual(fixed["facts_v2"][fixed["source"]["path"]]["ranges"][0]["maximum"], 64)
        self.assertIn("no causal security claim is made", " ".join(positive["limitations"]))


if __name__ == "__main__":
    unittest.main()
