"""Focused self-tests for portable manifest integrity and host reproduction."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "build_profile_manifest.py"
SPEC = importlib.util.spec_from_file_location("build_profile_manifest", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def blocked_manifest() -> dict:
    payload = {
        "schema": MODULE.PROFILE_SCHEMA,
        "status": "BLOCKED",
        "decision": "NOT_ADMITTED",
        "cases": [{
            "case_id": "SYNTHETIC",
            "build_profile": {"status": "BLOCKED"},
            "preprocess_profile": {"status": "BLOCKED"},
        }],
        "metrics": {"product_build_profile_complete_count": 0},
    }
    payload["payload_sha256"] = hashlib.sha256(MODULE.canonical_json_bytes(payload)).hexdigest()
    return payload


class ManifestIntegrityTests(unittest.TestCase):
    def test_valid_canonical_record_reports_integrity_only(self) -> None:
        result = MODULE.verify_manifest_integrity(blocked_manifest())
        self.assertEqual(result["manifest_integrity"], "valid")
        self.assertEqual(result["product_profile_status"], "BLOCKED")
        self.assertIn("no authenticity", result["scope_note"])

    def test_payload_mutation_is_detected(self) -> None:
        manifest = blocked_manifest()
        manifest["decision"] = "ADMITTED"
        result = MODULE.verify_manifest_integrity(manifest)
        self.assertEqual(result["manifest_integrity"], "invalid")
        self.assertIn("payload_digest_mismatch", result["errors"])
        self.assertIn("decision_not_not_admitted", result["errors"])

    def test_unblocked_product_status_is_rejected_even_with_recomputed_digest(self) -> None:
        manifest = blocked_manifest()
        manifest["cases"][0]["build_profile"]["status"] = "COMPLETE"
        manifest.pop("payload_sha256")
        manifest["payload_sha256"] = hashlib.sha256(MODULE.canonical_json_bytes(manifest)).hexdigest()
        result = MODULE.verify_manifest_integrity(manifest)
        self.assertEqual(result["manifest_integrity"], "invalid")
        self.assertTrue(any(error.startswith("build_profile_not_blocked") for error in result["errors"]))

    def test_environment_change_is_reported_as_drift_separately(self) -> None:
        expected = {"generated_from": {"ohscanner_head": "old"}, "host_toolchain_probe": {"python": "3.12"}}
        current = copy.deepcopy(expected)
        current["generated_from"]["ohscanner_head"] = "new"
        result = MODULE.compare_environment_fingerprints(expected, current)
        self.assertEqual(result["environment_reproduction"], "environment_drift")
        self.assertIn("generated_from.ohscanner_head", result["changed_paths"])
        self.assertNotEqual(result["expected_environment_fingerprint_sha256"], result["recomputed_environment_fingerprint_sha256"])

    def test_identical_environment_fingerprint_matches(self) -> None:
        manifest = {"generated_from": {"ohscanner_head": "same"}, "parser_identity": {"runtime": "host"}}
        result = MODULE.compare_environment_fingerprints(manifest, copy.deepcopy(manifest))
        self.assertEqual(result["environment_reproduction"], "environment_match")
        self.assertEqual(result["changed_paths"], [])


if __name__ == "__main__":
    unittest.main()
