from __future__ import annotations

import hashlib
import json
import unittest
from unittest.mock import patch

from research.experiments.cpp.bounds_length_parcel_slice import (
    ExperimentUnit,
    evaluate_slice,
)
from src.ohscanner.detectors.cpp.lifetime_detector import (
    LifetimeAnalysisOptions,
    LifetimeOwnershipGuardDetector,
)
from tests.detectors.fixture_support import (
    BOUNDS_FIXTURES,
    LIFETIME_FIXTURES,
    ROOT,
    lifetime_context,
    load_context,
    load_lifetime_units,
    load_manifest,
    load_units,
)


class ResearchSliceTests(unittest.TestCase):
    def test_manifest_hashes_bind_all_fixture_text(self) -> None:
        fixture_dirs = (
            ROOT / "tests" / "detectors" / "fixtures" / "cpp_lifetime",
            BOUNDS_FIXTURES,
        )
        for fixture_dir in fixture_dirs:
            manifest = json.loads((fixture_dir / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["schema_version"], 1)
            self.assertEqual(
                manifest["provenance"]["kind"],
                "self_authored_synthetic_fixture",
            )
            for item in manifest["units"]:
                text = (ROOT / item["path"]).read_text(encoding="utf-8")
                self.assertEqual(
                    hashlib.sha256(text.encode("utf-8")).hexdigest(),
                    item["sha256"],
                )

    def test_manifest_provenance_binds_fixture_context(self) -> None:
        for fixture_dir in (LIFETIME_FIXTURES, BOUNDS_FIXTURES):
            with self.subTest(fixture_dir=fixture_dir.name):
                manifest = load_manifest(fixture_dir)
                units = load_units(fixture_dir)
                context = load_context(fixture_dir, "test-fixture:provenance")
                provenance = manifest["provenance"]
                self.assertEqual(context.request.repository, provenance["repository"])
                self.assertEqual(context.request.commit, provenance["commit"])
                self.assertEqual(context.request.profile_id, provenance["profile_id"])
                self.assertEqual(
                    context.request.snapshot_sha256,
                    provenance["snapshot_sha256"],
                )
                self.assertEqual(context.units, units)

    def test_manifest_rejects_source_hash_mismatch(self) -> None:
        manifest = load_manifest(LIFETIME_FIXTURES)
        manifest["units"][0]["sha256"] = "0" * 64
        with patch(
            "tests.detectors.fixture_support.load_manifest",
            return_value=manifest,
        ):
            with self.assertRaisesRegex(ValueError, "manifest source hash mismatch"):
                load_units(LIFETIME_FIXTURES)

    def test_manifest_rejects_snapshot_mismatch(self) -> None:
        manifest = load_manifest(LIFETIME_FIXTURES)
        manifest["provenance"]["snapshot_sha256"] = "f" * 64
        with patch(
            "tests.detectors.fixture_support.load_manifest",
            return_value=manifest,
        ):
            with self.assertRaisesRegex(ValueError, "manifest snapshot hash mismatch"):
                load_units(LIFETIME_FIXTURES)

    def test_manifest_rejects_cross_fixture_unit_mixing(self) -> None:
        manifest = load_manifest(LIFETIME_FIXTURES)
        foreign = load_manifest(BOUNDS_FIXTURES)["units"][0]["path"]
        manifest["units"][0]["path"] = foreign
        with patch(
            "tests.detectors.fixture_support.load_manifest",
            return_value=manifest,
        ):
            with self.assertRaisesRegex(ValueError, "outside its manifest directory"):
                load_units(LIFETIME_FIXTURES)

    def test_manifest_rejects_duplicate_unit_paths(self) -> None:
        manifest = load_manifest(LIFETIME_FIXTURES)
        manifest["units"][1] = dict(manifest["units"][0])
        with patch(
            "tests.detectors.fixture_support.load_manifest",
            return_value=manifest,
        ):
            with self.assertRaisesRegex(ValueError, "duplicate fixture unit path"):
                load_units(LIFETIME_FIXTURES)

    def test_manifest_rejects_path_traversal(self) -> None:
        manifest = load_manifest(LIFETIME_FIXTURES)
        manifest["units"][0]["path"] = (
            "tests/detectors/fixtures/cpp_lifetime/../"
            "cpp_bounds_length_parcel/vulnerable_unbounded_parcel.cpp"
        )
        with patch(
            "tests.detectors.fixture_support.load_manifest",
            return_value=manifest,
        ):
            with self.assertRaisesRegex(ValueError, "outside its manifest directory"):
                load_units(LIFETIME_FIXTURES)

    def test_incomplete_parse_metadata_is_unknown_not_safe(self) -> None:
        for fixture_dir in (LIFETIME_FIXTURES, BOUNDS_FIXTURES):
            manifest = load_manifest(fixture_dir)
            for item in manifest["units"]:
                if item["parse_status"] != "complete":
                    with self.subTest(path=item["path"]):
                        self.assertEqual(
                            item["expected_observation"],
                            "unknown_incomplete_analysis",
                        )

    def test_bounds_slice_ablation_needs_guard_shape(self) -> None:
        manifest = json.loads((BOUNDS_FIXTURES / "manifest.json").read_text(encoding="utf-8"))
        units = tuple(
            ExperimentUnit(
                path=item["path"],
                text=(ROOT / item["path"]).read_text(encoding="utf-8"),
                parse_status=item["parse_status"],
            )
            for item in manifest["units"]
        )
        base = evaluate_slice(units, use_guard_shape=False)
        guarded = evaluate_slice(units, use_guard_shape=True)
        base_counts = {item.path: item.candidate_shapes for item in base}
        guarded_counts = {item.path: item.candidate_shapes for item in guarded}
        self.assertEqual(
            base_counts["tests/detectors/fixtures/cpp_bounds_length_parcel/vulnerable_unbounded_parcel.cpp"],
            1,
        )
        self.assertEqual(
            base_counts["tests/detectors/fixtures/cpp_bounds_length_parcel/fixed_guarded_parcel.cpp"],
            1,
        )
        self.assertEqual(
            guarded_counts["tests/detectors/fixtures/cpp_bounds_length_parcel/vulnerable_unbounded_parcel.cpp"],
            1,
        )
        self.assertEqual(
            guarded_counts["tests/detectors/fixtures/cpp_bounds_length_parcel/fixed_guarded_parcel.cpp"],
            0,
        )
        fixed = next(item for item in guarded if item.path.endswith("fixed_guarded_parcel.cpp"))
        self.assertTrue(fixed.guard_shape)
        self.assertTrue(any(item.kind == "upper_bound_guard_shape" for item in fixed.facts))
        self.assertTrue(any("not CFG dominance" in item for item in fixed.limitations))

    def test_lifetime_ablation_shows_alias_liveness_and_sync_contribution(self) -> None:
        units = load_lifetime_units()
        context = lifetime_context()
        base = LifetimeOwnershipGuardDetector(
            LifetimeAnalysisOptions(suppress_rebound_alias=False, classify_sync_scope=False)
        ).detect(context, units)
        alias = LifetimeOwnershipGuardDetector(
            LifetimeAnalysisOptions(suppress_rebound_alias=True, classify_sync_scope=False)
        ).detect(context, units)
        complete = LifetimeOwnershipGuardDetector(
            LifetimeAnalysisOptions(suppress_rebound_alias=True, classify_sync_scope=True)
        ).detect(context, units)
        self.assertEqual(len(base.findings), 4)
        self.assertEqual(len(alias.findings), 3)
        self.assertEqual(len(complete.findings), 3)
        self.assertTrue(all("sync_scope=not_classified" in item.message for item in base.findings))
        self.assertTrue(
            any("sync_scope=same_scoped_mutex_lock" in item.message for item in complete.findings)
        )


if __name__ == "__main__":
    unittest.main()
