"""Regeneration must not reinstate waived gates or invent execution evidence."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class DevelopmentTaskGenerationTests(unittest.TestCase):
    def test_real_portfolio_regeneration_does_not_require_product_or_staffing(self):
        root = Path(__file__).resolve().parents[1]
        profile = root / "research/methods/ark_runtime/build_profile_20261019/ark_parent_fix_build_profile_manifest.v1.json"
        inputs = json.loads(profile.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([
                sys.executable,
                str(root / "research/deliveries/product_closure_20261019/generate_product_closure.py"),
                "--profile-manifest", str(profile), "--output-dir", directory,
            ], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            tree = json.loads((Path(directory) / "task_tree.json").read_text(encoding="utf-8"))
            matrix = json.loads((Path(directory) / "product_closure_matrix.json").read_text(encoding="utf-8"))
        self.assertEqual(tree["status"], "ACTIVE_DEVELOPMENT")
        self.assertEqual(tree["blocking_prerequisites"], [])
        self.assertTrue(all(node["blocks_development"] is False for node in tree["nodes"]))
        self.assertEqual(len(tree["nodes"]), 6)
        self.assertEqual(matrix["case_count"], len(inputs["cases"]))
        self.assertEqual([case["case_id"] for case in matrix["cases"]],
                         [case["case_id"] for case in inputs["cases"]])
        for original, generated in zip(inputs["cases"], matrix["cases"]):
            self.assertEqual(generated["source_identity_status"], original.get("source_identity_status"))
            self.assertFalse(generated["admission"]["validated_vulnerability"])
            self.assertFalse(generated["admission"]["blocks_development"])
            self.assertEqual(generated["security_obligations"]["authorized_isolated_poc"], "not_run")
            self.assertEqual(generated["security_obligations"]["product_build_and_version"], "unknown")
        self.assertIsNone(matrix["metrics"]["precision"])
        self.assertIsNone(matrix["metrics"]["recall"])
        for artifact in (tree, matrix):
            digest = artifact.pop("payload_sha256")
            raw = json.dumps(artifact, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
            self.assertEqual(digest, hashlib.sha256(raw).hexdigest())
