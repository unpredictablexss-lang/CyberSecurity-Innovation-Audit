"""Public compatibility tests for A-CCR-03 layered Finding identity."""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from src.benchmark.tool_result import ToolDiagnostic
from src.ohscanner.identity import (
    RELATIONS,
    build_identity_record,
    compare_findings,
    line_byte_range,
    read_identity,
    stable_identity,
    occurrence_identity,
)


ROOT = Path(__file__).resolve().parents[1]
RESCAN = (
    ROOT
    / "outputs"
    / "reports"
    / "a_cpp_fixed_rescan_sharedptr050_lifetime040_20261015"
    / "comparison"
    / "comparison.json"
)


def observation(**overrides):
    record = {
        "repository": "openharmony/example",
        "commit": "a" * 40,
        "snapshot_sha256": "1" * 64,
        "profile_id": "light-ast",
        "legacy_diagnostic_id": "diag-before",
        "detector_id": "ohscanner.test.identity",
        "detector_version": "1.0.0",
        "rule_id": "rule.display",
        "rule_version": "1",
        "rule_lineage_id": "rule.lineage.stable",
        "symbol_identity": "ns::Widget::handle",
        "ast_fingerprint": "expr:shared_ptr-read",
        "identity_quality": "complete",
        "file": "src/widget.cpp",
        "line": 10,
        "message": "candidate before",
        "source_blob_oid": "b" * 40,
        "source_sha256": "c" * 64,
        "byte_start": 100,
        "byte_end": 160,
        "patch_region": {"status": "unknown", "method": None},
    }
    record.update(overrides)
    return record


def payload(**overrides):
    record = observation(**overrides)
    identity = build_identity_record(record)
    return {
        "schema_version": 2,
        "diagnostic_id": record["legacy_diagnostic_id"],
        "source_sha256": record["source_sha256"],
        "finding_identity_id": identity["stable"]["id"],
        "occurrence_id": identity["occurrence"]["id"],
        "finding_identity": identity,
    }


class StableIdentityTests(unittest.TestCase):
    def test_stable_identity_excludes_message_line_and_versions(self):
        base = observation()
        changed = observation(
            message="changed wording",
            line=99,
            byte_start=900,
            byte_end=960,
            detector_version="2.0.0",
            rule_version="2",
            source_blob_oid="d" * 40,
            source_sha256="e" * 64,
        )
        self.assertEqual(stable_identity(base)["id"], stable_identity(changed)["id"])
        self.assertNotEqual(occurrence_identity(base)["id"], occurrence_identity(changed)["id"])

    def test_same_member_names_have_distinct_stable_identity(self):
        left = observation(symbol_identity="ns::A::handle")
        right = observation(symbol_identity="ns::B::handle")
        self.assertNotEqual(stable_identity(left)["id"], stable_identity(right)["id"])

    def test_missing_or_partial_identity_fails_closed(self):
        for quality in ("partial", "failed", "unknown"):
            with self.subTest(quality=quality):
                result = stable_identity(observation(identity_quality=quality))
                self.assertEqual(result["status"], "unknown")
                self.assertIsNone(result["id"])
        missing = observation(rule_lineage_id=None, ast_fingerprint=None)
        result = stable_identity(missing)
        self.assertEqual(result["status"], "unknown")
        self.assertIn("missing:rule_lineage_id", result["unknown_reasons"])

    def test_occurrence_requires_exact_source_binding(self):
        base = observation()
        changed = observation(source_blob_oid="d" * 40, byte_start=200, byte_end=260)
        self.assertNotEqual(occurrence_identity(base)["id"], occurrence_identity(changed)["id"])
        self.assertEqual(occurrence_identity(base)["status"], "stable")
        self.assertEqual(occurrence_identity(changed)["status"], "stable")
        unbound = observation(source_blob_oid=None, byte_start=None, byte_end=None)
        self.assertEqual(occurrence_identity(unbound)["status"], "unknown")

    def test_occurrence_requires_nonempty_rule_version(self):
        for value in (None, ""):
            with self.subTest(rule_version=value):
                record = observation(rule_version=value)
                if value is None:
                    record.pop("rule_version")
                occurrence = occurrence_identity(record)
                self.assertEqual(occurrence["status"], "unknown")
                self.assertIn("missing:rule_version", occurrence["unknown_reasons"])
                self.assertEqual(build_identity_record(record)["source_binding"]["status"], "unbound")

    def test_line_byte_range_is_exact_utf8_half_open(self):
        text = "alpha\r\n界bc\nlast"
        start, end = line_byte_range(text, 2)
        encoded = text.encode("utf-8")
        self.assertEqual(encoded[start:end], "界bc\n".encode("utf-8"))


class RelationTests(unittest.TestCase):
    def test_identical_observation_is_persistent_unchanged(self):
        old = payload()
        new = payload()
        relation = compare_findings(
            [old], [new], before_coverage="complete", after_coverage="complete"
        )[0]
        self.assertEqual(relation["relation"], "persistent_unchanged")
        self.assertEqual(relation["vulnerability_effect"], "unknown")
        self.assertEqual(relation["changed_fields"], [])
    def test_comment_insertion_and_move_keep_stable_but_change_occurrence(self):
        old = payload()
        new = payload(
            legacy_diagnostic_id="diag-after-comment",
            line=15,
            message="same semantics after comment",
            source_blob_oid="d" * 40,
            source_sha256="e" * 64,
            byte_start=300,
            byte_end=360,
            patch_region={"status": "mapped", "method": "hunk+symbol+ast"},
        )
        relation = compare_findings(
            [old], [new], before_coverage="complete", after_coverage="complete"
        )[0]
        self.assertEqual(relation["relation"], "persistent_moved_or_changed")
        self.assertEqual(relation["vulnerability_effect"], "unknown")
        self.assertIn("message", relation["changed_fields"])
        self.assertEqual(len(relation["historical_ids"]), 2)

    def test_message_change_is_metadata_not_repair(self):
        old = payload()
        new = payload(
            legacy_diagnostic_id="diag-after-message",
            message="new wording",
        )
        relation = compare_findings(
            [old], [new], before_coverage="complete", after_coverage="complete"
        )[0]
        self.assertEqual(relation["relation"], "persistent_changed_metadata")
        self.assertEqual(relation["vulnerability_effect"], "unknown")
        self.assertIn("message", relation["changed_fields"])

    def test_duplicate_anchor_is_ambiguous(self):
        first = payload(line=10, message="anchor one")
        second = payload(line=20, message="anchor two")
        relation = compare_findings(
            [first, second], [], before_coverage="complete", after_coverage="complete"
        )[0]
        self.assertEqual(relation["relation"], "unknown_identity_ambiguous")
        self.assertEqual(relation["vulnerability_effect"], "unknown")

    def test_partial_failed_unknown_never_become_absent(self):
        for quality in ("partial", "failed", "unknown"):
            record = payload(identity_quality=quality)
            relation = compare_findings(
                [record], [], before_coverage=quality, after_coverage=quality
            )[0]
            self.assertEqual(relation["relation"], "unknown_identity")
            self.assertNotIn("observation_absent", relation["relation"])

    def test_absent_and_added_are_comparable_only_with_complete_coverage(self):
        old, new = payload(), payload(
            legacy_diagnostic_id="new-only",
            symbol_identity="ns::Widget::other",
            ast_fingerprint="expr:other",
        )
        absent = compare_findings(
            [old], [], before_coverage="complete", after_coverage="complete",
            rule_compatibility="compatible",
        )[0]
        added = compare_findings(
            [], [new], before_coverage="complete", after_coverage="complete",
            rule_compatibility="compatible",
        )[0]
        self.assertEqual(absent["relation"], "observation_absent_comparable")
        self.assertEqual(added["relation"], "observation_added_comparable")
        self.assertEqual(absent["vulnerability_effect"], "unknown")
        self.assertEqual(added["vulnerability_effect"], "unknown")

    def test_partial_coverage_is_not_comparable(self):
        relation = compare_findings(
            [payload()], [], before_coverage="complete", after_coverage="partial",
            rule_compatibility="compatible",
        )[0]
        self.assertEqual(relation["relation"], "unknown_not_comparable")
        self.assertEqual(relation["vulnerability_effect"], "unknown")

    def test_version_boundary_is_unknown_without_explicit_compatibility(self):
        old = payload()
        new = payload(detector_version="2.0.0", rule_version="2")
        relation = compare_findings(
            [old], [new], before_coverage="complete", after_coverage="complete"
        )[0]
        self.assertEqual(relation["relation"], "unknown_version_boundary")
        explicit = compare_findings(
            [old], [new], before_coverage="complete", after_coverage="complete",
            rule_compatibility="compatible",
        )[0]
        self.assertEqual(explicit["relation"], "persistent_changed_metadata")

    def test_missing_rule_version_never_establishes_compatibility(self):
        for value in (None, ""):
            with self.subTest(rule_version=value):
                before_record = observation(rule_version=value)
                after_record = observation(rule_version=value)
                if value is None:
                    before_record.pop("rule_version")
                    after_record.pop("rule_version")

                def as_payload(record):
                    identity = build_identity_record(record)
                    return {
                        "schema_version": 2,
                        "diagnostic_id": record["legacy_diagnostic_id"],
                        "source_sha256": record["source_sha256"],
                        "finding_identity_id": identity["stable"]["id"],
                        "occurrence_id": identity["occurrence"]["id"],
                        "finding_identity": identity,
                    }

                relation = compare_findings(
                    [as_payload(before_record)], [as_payload(after_record)],
                    before_coverage="complete", after_coverage="complete",
                )[0]
                expected_relation = (
                    "unknown_version_boundary" if value is None else "unknown_identity"
                )
                self.assertEqual(relation["relation"], expected_relation)
                self.assertFalse(relation["relation"].startswith("persistent_"))
                self.assertEqual(relation["vulnerability_effect"], "unknown")
                if value is None:
                    self.assertIn("rule_compatibility:unknown", relation["reasons"])

    def test_relation_vocabulary_is_exactly_supported(self):
        self.assertTrue({
            "persistent_unchanged",
            "persistent_changed_metadata",
            "persistent_moved_or_changed",
            "observation_absent_comparable",
            "observation_added_comparable",
            "unknown_identity",
            "unknown_identity_ambiguous",
        }.issubset(RELATIONS))


class CompatibilityTests(unittest.TestCase):
    def test_v1_diagnostic_reads_unknown_without_backfill(self):
        diagnostic = ToolDiagnostic(
            diagnostic_id="legacy:v1:1", provider="legacy", evidence_type="pattern",
            file="src/a.cpp", line=1, column=None, rule_id="r", severity="warning",
            message="legacy",
        ).to_dict()
        self.assertNotIn("finding_identity", diagnostic)
        read = read_identity(diagnostic, schema_version=1)
        self.assertFalse(read["backfilled"])
        self.assertEqual(read["legacy_diagnostic_id"], "legacy:v1:1")
        self.assertEqual(read["stable"]["status"], "unknown")
        self.assertEqual(read["occurrence"]["status"], "unknown")
        self.assertEqual(read["source_binding"], "unbound")

    def test_v2_without_identity_reads_unknown_but_keeps_source_binding(self):
        diagnostic = ToolDiagnostic(
            diagnostic_id="v2:1", provider="own", evidence_type="syntax",
            file="src/a.cpp", line=1, column=None, rule_id="r", severity="unassessed",
            message="v2", source_sha256="a" * 64,
        ).to_dict()
        self.assertNotIn("finding_identity", diagnostic)
        read = read_identity(diagnostic, schema_version=2)
        self.assertFalse(read["backfilled"])
        self.assertEqual(read["source_binding"], "bound")
        self.assertEqual(read["stable"]["status"], "unknown")

    def test_v2_identity_reader_preserves_ids_and_detects_tampering(self):
        original = payload()
        read = read_identity(original)
        self.assertEqual(read["finding_identity_id"], original["finding_identity_id"])
        self.assertEqual(read["occurrence_id"], original["occurrence_id"])
        tampered = dict(original, finding_identity_id="ohfi:v1:deadbeef")
        read = read_identity(tampered)
        self.assertEqual(read["stable"]["status"], "unknown")
        self.assertIn("finding_identity_id_mismatch", read["reasons"])

    def test_optional_identity_fields_are_omitted_from_legacy_to_dict(self):
        legacy = ToolDiagnostic(
            diagnostic_id="legacy", provider="legacy", evidence_type="pattern",
            file="src/a.cpp", line=1, column=None, rule_id="r", severity="warning",
            message="legacy",
        ).to_dict()
        self.assertNotIn("finding_identity_id", legacy)
        self.assertNotIn("occurrence_id", legacy)
        self.assertNotIn("finding_identity", legacy)


@unittest.skipUnless(RESCAN.exists(), "same-scope rescan artifact is not present in this checkout")
class SameScopeRescanRegressionTests(unittest.TestCase):
    def test_existing_rescan_counts_and_identity_gap_are_preserved(self):
        raw = RESCAN.read_bytes()
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(),
            "c7da13895f4ed08abf19eadefdea871c1633bf9a3f15833567034129a69d62e4",
        )
        data = json.loads(raw.decode("utf-8"))
        counts = {
            "old": 0,
            "new": 0,
            "added": 0,
            "disappeared": 0,
            "changed": 0,
            "unchanged": 0,
        }
        changed_fields = []
        rows = []
        for component in data["components"]:
            for key in counts:
                counts[key] += int(component["candidate_counts"][key])
            rows.extend(component["changed"])
        self.assertEqual(counts, {
            "old": 208, "new": 182, "added": 0, "disappeared": 26,
            "changed": 182, "unchanged": 0,
        })
        for row in rows:
            changed_fields.append(tuple(sorted(row["changed_fields"])))
            self.assertNotIn("finding_identity_id", row["old"])
            self.assertNotIn("finding_identity_id", row["new"])
        self.assertEqual(set(changed_fields), {("diagnostic_id", "message")})
        self.assertTrue(data["interpretation"]["candidate_decrease_is_not_safety"])
        self.assertTrue(data["interpretation"]["version_difference_is_not_fix_or_accuracy"])
        self.assertEqual(data["interpretation"]["precision_recall"], "not_computed")


if __name__ == "__main__":
    unittest.main()
