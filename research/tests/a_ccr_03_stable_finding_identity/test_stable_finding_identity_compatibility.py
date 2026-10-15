"""Draft compatibility tests for A-CCR-03 stable Finding identity.

Run from the repository root with:
  wsl.exe -e bash -lc "cd /mnt/e/网安/CyberSecurity-Innovation-Audit && .venv-web/bin/python -m unittest discover -s research/tests/a_ccr_03_stable_finding_identity -v"
The tests exercise a research-only reference model. They do not import or alter
src/ohscanner public contracts, runner, catalog, or analysis modules.
"""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


REFERENCE_PATH = (
    Path(__file__).resolve().parents[2]
    / "experiments"
    / "cpp"
    / "a_ccr_03_stable_finding_identity_20261015"
    / "identity_reference.py"
)
SPEC = importlib.util.spec_from_file_location("a_ccr_03_identity_reference", REFERENCE_PATH)
assert SPEC and SPEC.loader
identity = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(identity)


class StableFindingIdentityCompatibilityTests(unittest.TestCase):
    def test_inserting_comment_changes_occurrence_but_not_stable_identity(self):
        old = identity.make_observation(
            legacy_diagnostic_id="diag-before",
            line=2,
            source_blob_oid="blob-before",
            source_sha256="b" * 64,
            byte_start=10,
            byte_end=20,
        )
        new = identity.make_observation(
            legacy_diagnostic_id="diag-after-comment",
            line=5,
            source_blob_oid="blob-after-comment",
            source_sha256="c" * 64,
            byte_start=31,
            byte_end=41,
            patch_region={"status": "mapped", "method": "hunk+symbol+ast"},
        )
        self.assertEqual(
            identity.stable_identity(old)["id"],
            identity.stable_identity(new)["id"],
        )
        self.assertNotEqual(
            identity.occurrence_identity(old)["id"],
            identity.occurrence_identity(new)["id"],
        )
        relation = identity.compare([old], [new])[0]
        self.assertEqual(relation["relation"], "persistent_moved_or_changed")
        self.assertEqual(relation["vulnerability_effect"], "unknown")

    def test_message_change_does_not_change_stable_identity_or_drop_historical_id(self):
        old = identity.make_observation(
            legacy_diagnostic_id="diag-message-before",
            message="old wording",
            historical_ids=["semgrep:legacy-1"],
        )
        new = identity.make_observation(
            legacy_diagnostic_id="diag-message-after",
            message="new wording",
        )
        self.assertEqual(
            identity.stable_identity(old)["id"],
            identity.stable_identity(new)["id"],
        )
        relation = identity.compare([old], [new])[0]
        self.assertEqual(relation["relation"], "persistent_changed_metadata")
        self.assertIn("diagnostic_id", relation["changed_fields"])
        self.assertIn("message", relation["changed_fields"])
        prepared = identity.prepare(old)
        self.assertEqual(
            prepared["legacy_identity"]["aliases"],
            ["semgrep:legacy-1", "diag-message-before"],
        )

    def test_moving_expression_keeps_identity_when_patch_region_maps_it(self):
        old = identity.make_observation(
            line=20,
            source_blob_oid="blob-before-move",
            byte_start=200,
            byte_end=218,
        )
        new = identity.make_observation(
            line=87,
            source_blob_oid="blob-after-move",
            byte_start=870,
            byte_end=888,
            patch_region={"status": "mapped", "method": "patch-hunk+symbol+ast"},
        )
        self.assertEqual(
            identity.stable_identity(old)["id"],
            identity.stable_identity(new)["id"],
        )
        self.assertEqual(
            identity.compare([old], [new])[0]["relation"],
            "persistent_moved_or_changed",
        )

    def test_same_member_name_across_class_or_namespace_stays_distinct(self):
        left = identity.make_observation(
            symbol_identity="ns::A::handle",
            ast_fingerprint="expr:member-read",
        )
        right = identity.make_observation(
            symbol_identity="ns::B::handle",
            ast_fingerprint="expr:member-read",
        )
        self.assertNotEqual(
            identity.stable_identity(left)["id"],
            identity.stable_identity(right)["id"],
        )

    def test_partial_failed_unknown_never_becomes_disappeared(self):
        old = identity.make_observation(identity_quality="partial")
        for coverage in ("partial", "failed", "unknown"):
            relation = identity.compare(
                [old], [], before_coverage="partial", after_coverage=coverage
            )[0]
            self.assertEqual(relation["relation"], "unknown_identity")
            self.assertEqual(relation["vulnerability_effect"], "unknown")
            self.assertNotIn("observation_absent", relation["relation"])

    def test_historical_v1_id_is_retained_but_cannot_invent_stable_identity(self):
        v1 = identity.make_observation(
            legacy_schema_version=1,
            legacy_diagnostic_id="semgrep:historical-42",
            source_sha256="",
            source_blob_oid="",
            byte_start=None,
            byte_end=None,
            identity_quality="unknown",
        )
        prepared = identity.prepare(v1)
        self.assertEqual(prepared["finding_identity"]["status"], "unknown")
        self.assertEqual(prepared["occurrence_identity"]["status"], "unknown")
        self.assertEqual(prepared["legacy_identity"]["source_binding"], "unbound")
        self.assertEqual(prepared["legacy_identity"]["diagnostic_id"], "semgrep:historical-42")
        self.assertEqual(prepared["legacy_identity"]["aliases"], ["semgrep:historical-42"])

    def test_same_source_position_across_detector_versions_requires_lineage_compatibility(self):
        old = identity.make_observation(
            legacy_diagnostic_id="diag-v04",
            detector_version="0.4.0",
            rule_version="1",
            message="candidate wording v04",
        )
        new = identity.make_observation(
            legacy_diagnostic_id="diag-v05",
            detector_version="0.5.0",
            rule_version="2",
            message="candidate wording v05",
        )
        self.assertEqual(
            identity.stable_identity(old)["id"],
            identity.stable_identity(new)["id"],
        )
        self.assertEqual(
            identity.compare([old], [new], rule_compatibility="compatible")[0]["relation"],
            "persistent_changed_metadata",
        )
        self.assertEqual(
            identity.compare([old], [new], rule_compatibility="unknown")[0]["relation"],
            "unknown_version_boundary",
        )

    def test_duplicate_semantic_anchors_are_not_forced_to_pair(self):
        one = identity.make_observation(legacy_diagnostic_id="dup-1")
        two = identity.make_observation(legacy_diagnostic_id="dup-2")
        after = identity.make_observation(legacy_diagnostic_id="dup-after")
        self.assertEqual(
            identity.stable_identity(one)["id"],
            identity.stable_identity(two)["id"],
        )
        relation = identity.compare([one, two], [after])[0]
        self.assertEqual(relation["relation"], "unknown_identity_ambiguous")
        self.assertEqual(relation["vulnerability_effect"], "unknown")

    def test_observation_absence_is_not_a_vulnerability_fix_claim(self):
        old = identity.make_observation(legacy_diagnostic_id="old-only")
        relation = identity.compare(
            [old], [], before_coverage="complete", after_coverage="complete"
        )[0]
        self.assertEqual(relation["relation"], "observation_absent_comparable")
        self.assertEqual(relation["vulnerability_effect"], "unknown")


if __name__ == "__main__":
    unittest.main()
