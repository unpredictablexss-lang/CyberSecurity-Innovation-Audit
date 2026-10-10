from __future__ import annotations

import copy
import hashlib
import unittest

from src.ohscanner.holdout_manifest import (
    DESIGNED_NOT_EXECUTED,
    DETECTOR_ID,
    _REQUIRED_STRATA,
    canonical_sha256,
    validate_design_manifest,
    validate_evidence_bundle,
    validate_prediction_manifest,
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _case(stratum: str, index: int) -> dict:
    pair = stratum in {"pair_slot_a", "pair_slot_b"}
    return {
        "case_id": f"holdout-{index:02d}",
        "stratum": stratum,
        "pair_id": "external-pair-001" if pair else None,
        "repository": "external/project",
        "commit": _sha(f"commit-{index}")[:40],
        "path": "external/pair.cpp" if pair else f"external/case-{index:02d}.cpp",
        "source_sha256": _sha(f"source-{index}"),
        "snapshot_sha256": _sha(f"snapshot-{index}"),
        "profile_id": "light-ast",
        "tool_id": DETECTOR_ID,
        "tool_version": "0.1.0-proposed",
        "development_participation": "not_participated",
        "label_visibility": "sealed_from_detector",
    }


def _manifest() -> dict:
    return {
        "schema_version": 1,
        "holdout_id": "shared-ptr-race-external-holdout",
        "status": DESIGNED_NOT_EXECUTED,
        "detector_freeze": {
            "detector_id": DETECTOR_ID,
            "detector_version": "0.1.0-proposed",
            "detector_sha256": _sha("detector"),
            "rule_sha256": _sha("rule"),
            "method_sha256": _sha("method"),
            "frozen_at_utc": "2026-10-10T00:00:00Z",
        },
        "independence": {
            "development_fixtures_reused": False,
            "labels_visible_during_prediction": False,
            "label_adjustment_after_prediction": False,
            "selection_record_sha256": _sha("selection"),
            "exclusion_audit_sha256": _sha("exclusion-audit"),
        },
        "cases": [
            _case(stratum, index)
            for index, stratum in enumerate(sorted(_REQUIRED_STRATA), start=1)
        ],
        "prediction_sha256": None,
        "label_release_sha256": None,
    }


class SharedPtrRaceHoldoutManifestTests(unittest.TestCase):
    def test_accepts_designed_not_executed_external_manifest(self) -> None:
        manifest = _manifest()
        self.assertIs(validate_design_manifest(manifest), manifest)

    def test_rejects_missing_or_nonexact_bindings(self) -> None:
        cases = [
            ("repository", "not-a-repository"),
            ("commit", "short"),
            ("path", "../outside.cpp"),
            ("source_sha256", "not-a-sha"),
            ("snapshot_sha256", "not-a-sha"),
            ("profile_id", ""),
            ("tool_id", "another.detector"),
            ("tool_version", "different-version"),
        ]
        for field, value in cases:
            with self.subTest(field=field):
                manifest = _manifest()
                manifest["cases"][0][field] = value
                with self.assertRaises(ValueError):
                    validate_design_manifest(manifest)

    def test_rejects_mixed_evidence_groups(self) -> None:
        groups = sorted(
            {"vulnerable", "fixed", "safe", "unrelated", "unknown", "not_applicable"}
        )
        case = _manifest()["cases"][0]
        for left_index, left in enumerate(groups):
            for right in groups[left_index + 1:]:
                with self.subTest(groups=(left, right)):
                    records = []
                    for index, group in enumerate((left, right), start=1):
                        record = copy.deepcopy(case)
                        record.update(
                            {
                                "evidence_id": f"evidence-{index}",
                                "run_id": f"run-{index}",
                                "evidence_group": group,
                            }
                        )
                        records.append(record)
                    bundle = {
                        "bundle_id": "mixed-bundle",
                        "evidence_group": left,
                        "records": records,
                    }
                    with self.assertRaisesRegex(ValueError, "cannot be mixed"):
                        validate_evidence_bundle(bundle)

    def test_partial_failed_not_run_are_unknown_and_not_applicable_needs_proof(self) -> None:
        design = _manifest()
        by_stratum = {item["stratum"]: item for item in design["cases"]}
        prediction = {
            "schema_version": 1,
            "holdout_id": design["holdout_id"],
            "detector_freeze_sha256": canonical_sha256(design["detector_freeze"]),
            "cases": [],
        }
        for case in design["cases"]:
            status = "complete"
            observation = "no_observed_candidate_shape"
            item = {
                "case_id": case["case_id"],
                "run_id": "run-" + case["case_id"],
                "analysis_status": status,
                "raw_observation": observation,
                "diagnostic_count": 0,
            }
            if case["stratum"] == "analysis_partial":
                item["analysis_status"] = "partial"
                item["raw_observation"] = "unknown_incomplete_analysis"
            elif case["stratum"] == "analysis_failed":
                item["analysis_status"] = "failed"
                item["raw_observation"] = "unknown_incomplete_analysis"
            elif case["stratum"] == "analysis_not_run":
                item["analysis_status"] = "not_run"
                item["raw_observation"] = "unknown_incomplete_analysis"
            elif case["stratum"] == "incompatible_unit":
                item["analysis_status"] = "not_applicable"
                item["raw_observation"] = "not_applicable"
                item["incompatibility"] = {
                    "kind": "unsupported_language",
                    "proof_sha256": _sha("incompatibility-proof"),
                }
            prediction["cases"].append(item)
        validate_prediction_manifest(prediction, design)

        invalid = copy.deepcopy(prediction)
        target = next(
            item for item in invalid["cases"]
            if item["case_id"] == by_stratum["analysis_not_run"]["case_id"]
        )
        target["raw_observation"] = "no_observed_candidate_shape"
        with self.assertRaisesRegex(ValueError, "must remain unknown"):
            validate_prediction_manifest(invalid, design)

        invalid = copy.deepcopy(prediction)
        target = next(
            item for item in invalid["cases"]
            if item["case_id"] == by_stratum["incompatible_unit"]["case_id"]
        )
        del target["incompatibility"]
        with self.assertRaisesRegex(ValueError, "requires an evidenced incompatibility"):
            validate_prediction_manifest(invalid, design)


if __name__ == "__main__":
    unittest.main()
