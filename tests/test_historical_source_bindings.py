import json
from pathlib import Path
import unittest

from scripts.verify_historical_source_bindings import _validate_local_shape


ROOT = Path(__file__).resolve().parents[1]


class HistoricalSourceBindingTests(unittest.TestCase):
    def test_three_verified_cve_pairs_are_fully_bound_locally(self) -> None:
        samples = {
            json.loads(path.read_text(encoding="utf-8"))["sample_id"]: json.loads(
                path.read_text(encoding="utf-8")
            )
            for path in (ROOT / "benchmarks/historical").glob("*.json")
        }
        bindings = sorted((ROOT / "benchmarks/historical/source_bindings").glob("*.json"))
        self.assertEqual(len(bindings), 3)
        for path in bindings:
            binding = json.loads(path.read_text(encoding="utf-8"))
            sample = samples[binding["sample_id"]]
            _validate_local_shape(sample, binding)
            self.assertEqual(sample["label_status"], "advisory_confirmed")
            self.assertEqual(sample["evidence_level"], "patch_and_advisory")
            self.assertNotEqual(binding["vulnerable_blob_sha1"], binding["fixed_blob_sha1"])
            self.assertNotEqual(binding["vulnerable_sha256"], binding["fixed_sha256"])

    def test_binding_mismatch_is_rejected(self) -> None:
        path = next((ROOT / "benchmarks/historical/source_bindings").glob("*.json"))
        binding = json.loads(path.read_text(encoding="utf-8"))
        sample_path = next(
            candidate for candidate in (ROOT / "benchmarks/historical").glob("*.json")
            if json.loads(candidate.read_text(encoding="utf-8")).get("sample_id")
            == binding["sample_id"]
        )
        sample = json.loads(sample_path.read_text(encoding="utf-8"))
        binding["fixed_blob_sha1"] = "0" * 40
        with self.assertRaisesRegex(ValueError, "fixed_blob_sha1"):
            _validate_local_shape(sample, binding)


if __name__ == "__main__":
    unittest.main()
