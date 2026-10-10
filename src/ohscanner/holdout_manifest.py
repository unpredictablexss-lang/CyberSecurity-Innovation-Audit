from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Mapping, Sequence

from src.ohscanner.contracts import safe_relative_path


SCHEMA_VERSION = 1
DETECTOR_ID = "ohscanner.cpp.shared_ptr_race"
DESIGNED_NOT_EXECUTED = "designed_not_executed"
_ALLOWED_MANIFEST_STATUSES = {
    DESIGNED_NOT_EXECUTED,
    "prediction_sealed",
    "labels_revealed",
}
_ALLOWED_GROUPS = {
    "vulnerable",
    "fixed",
    "safe",
    "unrelated",
    "unknown",
    "not_applicable",
}
_REQUIRED_STRATA = {
    "pair_slot_a",
    "pair_slot_b",
    "similar_safe_control",
    "unrelated_shared_ptr",
    "local_shared_ptr",
    "same_name_different_class",
    "atomic_helper",
    "mutex_wrapper",
    "initialized_readonly",
    "analysis_partial",
    "analysis_failed",
    "analysis_not_run",
    "incompatible_unit",
}
_STRATUM_GROUP = {
    "pair_slot_a": "vulnerable",
    "pair_slot_b": "fixed",
    "similar_safe_control": "safe",
    "unrelated_shared_ptr": "unrelated",
    "local_shared_ptr": "unrelated",
    "same_name_different_class": "unrelated",
    "atomic_helper": "safe",
    "mutex_wrapper": "safe",
    "initialized_readonly": "safe",
    "analysis_partial": "unknown",
    "analysis_failed": "unknown",
    "analysis_not_run": "unknown",
    "incompatible_unit": "not_applicable",
}
_RAW_OBSERVATIONS = {
    "possible_hit",
    "no_observed_candidate_shape",
    "unknown_incomplete_analysis",
    "not_applicable",
}
_ANALYSIS_STATUSES = {
    "complete",
    "partial",
    "failed",
    "not_run",
    "not_applicable",
}
_FORBIDDEN_PREDICTION_KEYS = {
    "label",
    "labels",
    "evidence_group",
    "ground_truth",
    "expected_observation",
    "fixture_category",
}
_COMMIT_RE = re.compile(r"(?:[a-f0-9]{40}|[a-f0-9]{64})")
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_SHA256_RE = re.compile(r"[a-f0-9]{64}")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _require_sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ValueError(f"{field} must be a lowercase SHA-256")
    return value


def _require_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise ValueError(f"{field} must be a safe identifier")
    return value


def _require_commit(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _COMMIT_RE.fullmatch(value):
        raise ValueError(f"{field} must be a full lowercase Git commit SHA")
    return value


def _require_repository(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value)
    ):
        raise ValueError(f"{field} must be an owner/repository name")
    return value


def _require_object(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be an object")
    return value


def _validate_binding(item: Mapping[str, Any], *, prefix: str) -> None:
    _require_repository(item.get("repository"), f"{prefix}.repository")
    _require_commit(item.get("commit"), f"{prefix}.commit")
    safe_relative_path(item.get("path"))
    _require_sha256(item.get("source_sha256"), f"{prefix}.source_sha256")
    _require_sha256(item.get("snapshot_sha256"), f"{prefix}.snapshot_sha256")
    profile_id = item.get("profile_id")
    if not isinstance(profile_id, str) or not profile_id.strip():
        raise ValueError(f"{prefix}.profile_id is required")
    if item.get("tool_id") != DETECTOR_ID:
        raise ValueError(f"{prefix}.tool_id must match the frozen detector")
    tool_version = item.get("tool_version")
    if not isinstance(tool_version, str) or not tool_version.strip():
        raise ValueError(f"{prefix}.tool_version is required")


def _validate_freeze(value: Any) -> Mapping[str, Any]:
    freeze = _require_object(value, "detector_freeze")
    if freeze.get("detector_id") != DETECTOR_ID:
        raise ValueError("detector_freeze.detector_id is incompatible")
    _require_id(freeze.get("detector_version"), "detector_freeze.detector_version")
    for field in ("detector_sha256", "rule_sha256", "method_sha256"):
        _require_sha256(freeze.get(field), f"detector_freeze.{field}")
    frozen_at = freeze.get("frozen_at_utc")
    if not isinstance(frozen_at, str) or not frozen_at.strip():
        raise ValueError("detector_freeze.frozen_at_utc is required")
    return freeze


def validate_design_manifest(manifest: Any) -> Mapping[str, Any]:
    data = _require_object(manifest, "holdout manifest")
    if data.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported holdout manifest schema_version")
    holdout_id = _require_id(data.get("holdout_id"), "holdout_id")
    status = data.get("status")
    if status not in _ALLOWED_MANIFEST_STATUSES:
        raise ValueError("unsupported holdout status")
    freeze = _validate_freeze(data.get("detector_freeze"))

    independence = _require_object(data.get("independence"), "independence")
    if independence.get("development_fixtures_reused") is not False:
        raise ValueError("development fixtures must be excluded from holdout")
    if independence.get("labels_visible_during_prediction") is not False:
        raise ValueError("labels must remain hidden during prediction")
    if independence.get("label_adjustment_after_prediction") is not False:
        raise ValueError("holdout labels cannot be adjusted after prediction")
    for field in ("selection_record_sha256", "exclusion_audit_sha256"):
        _require_sha256(independence.get(field), f"independence.{field}")

    cases = data.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("holdout manifest requires external cases")
    seen_ids = set()
    seen_strata = set()
    for index, raw_case in enumerate(cases):
        case = _require_object(raw_case, f"cases[{index}]")
        case_id = _require_id(case.get("case_id"), f"cases[{index}].case_id")
        if case_id in seen_ids:
            raise ValueError("duplicate holdout case_id")
        seen_ids.add(case_id)
        stratum = case.get("stratum")
        if stratum not in _REQUIRED_STRATA:
            raise ValueError(f"cases[{index}].stratum is not a required holdout stratum")
        seen_strata.add(stratum)
        if case.get("development_participation") != "not_participated":
            raise ValueError("holdout case participated in detector development")
        if case.get("label_visibility") != "sealed_from_detector":
            raise ValueError("holdout case labels must be sealed from the detector")
        _validate_binding(case, prefix=f"cases[{index}]")
        if case.get("tool_version") != freeze["detector_version"]:
            raise ValueError("case tool_version does not match detector freeze")

    missing = sorted(_REQUIRED_STRATA - seen_strata)
    if missing:
        raise ValueError("holdout manifest missing required strata: " + ", ".join(missing))

    pair_cases = [
        item for item in cases
        if item.get("stratum") in {"pair_slot_a", "pair_slot_b"}
    ]
    pair_ids = {item.get("pair_id") for item in pair_cases}
    if len(pair_cases) != 2 or len(pair_ids) != 1 or None in pair_ids:
        raise ValueError("vulnerable/fixed pair slots must share one external pair_id")
    pair_binding_fields = ("repository", "path", "profile_id", "tool_id", "tool_version")
    if any(
        len({item.get(field) for item in pair_cases}) != 1
        for field in pair_binding_fields
    ):
        raise ValueError("vulnerable/fixed pair must bind the same repository path and profile")
    if pair_cases[0].get("commit") == pair_cases[1].get("commit"):
        raise ValueError("vulnerable/fixed pair must bind distinct commits")

    prediction_sha256 = data.get("prediction_sha256")
    label_release_sha256 = data.get("label_release_sha256")
    if status == DESIGNED_NOT_EXECUTED:
        if prediction_sha256 is not None or label_release_sha256 is not None:
            raise ValueError("designed_not_executed cannot contain prediction or label hashes")
    elif status == "prediction_sealed":
        _require_sha256(prediction_sha256, "prediction_sha256")
        if label_release_sha256 is not None:
            raise ValueError("labels cannot be bound before the prediction is sealed")
    else:
        _require_sha256(prediction_sha256, "prediction_sha256")
        _require_sha256(label_release_sha256, "label_release_sha256")
    return data


def validate_prediction_manifest(
    prediction: Any,
    design_manifest: Mapping[str, Any],
) -> Mapping[str, Any]:
    validate_design_manifest(design_manifest)
    data = _require_object(prediction, "prediction manifest")
    if data.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported prediction manifest schema_version")
    if data.get("holdout_id") != design_manifest["holdout_id"]:
        raise ValueError("prediction holdout_id mismatch")
    freeze_hash = canonical_sha256(design_manifest["detector_freeze"])
    if data.get("detector_freeze_sha256") != freeze_hash:
        raise ValueError("prediction detector freeze mismatch")

    def reject_labels(value: Any, path: str = "$") -> None:
        if isinstance(value, Mapping):
            for key, child in value.items():
                if key in _FORBIDDEN_PREDICTION_KEYS:
                    raise ValueError(f"unlabeled prediction contains forbidden key {path}.{key}")
                reject_labels(child, f"{path}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                reject_labels(child, f"{path}[{index}]")

    reject_labels(data)
    expected_ids = {item["case_id"] for item in design_manifest["cases"]}
    cases = data.get("cases")
    if not isinstance(cases, list):
        raise ValueError("prediction cases are required")
    seen = set()
    for index, raw_case in enumerate(cases):
        case = _require_object(raw_case, f"prediction.cases[{index}]")
        case_id = case.get("case_id")
        if case_id not in expected_ids or case_id in seen:
            raise ValueError("prediction case_id is unknown or duplicated")
        seen.add(case_id)
        analysis_status = case.get("analysis_status")
        raw_observation = case.get("raw_observation")
        if analysis_status not in _ANALYSIS_STATUSES:
            raise ValueError("prediction analysis_status is invalid")
        if raw_observation not in _RAW_OBSERVATIONS:
            raise ValueError("prediction raw_observation is invalid")
        count = case.get("diagnostic_count")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("prediction diagnostic_count must be a non-negative integer")
        if analysis_status in {"partial", "failed", "not_run"}:
            if raw_observation != "unknown_incomplete_analysis":
                raise ValueError("partial/failed/not_run analysis must remain unknown")
        elif analysis_status == "not_applicable":
            if raw_observation != "not_applicable":
                raise ValueError("not_applicable analysis cannot become a hit or miss")
            if not isinstance(case.get("incompatibility"), Mapping):
                raise ValueError(
                    "not_applicable requires an evidenced incompatibility proof"
                )
            incompatibility = case["incompatibility"]
            kind = incompatibility.get("kind")
            if kind not in {
                "unsupported_language",
                "incompatible_analysis_unit",
                "outside_detector_contract",
            }:
                raise ValueError("not_applicable requires an evidenced incompatibility kind")
            _require_sha256(
                incompatibility.get("proof_sha256"),
                "prediction.incompatibility.proof_sha256",
            )
        elif raw_observation not in {"possible_hit", "no_observed_candidate_shape"}:
            raise ValueError("complete analysis has an invalid raw observation")
    if seen != expected_ids:
        raise ValueError("prediction must cover every holdout case exactly once")
    return data


def validate_evidence_bundle(bundle: Any) -> Mapping[str, Any]:
    data = _require_object(bundle, "evidence bundle")
    group = data.get("evidence_group")
    if group not in _ALLOWED_GROUPS:
        raise ValueError("invalid evidence group")
    records = data.get("records")
    if not isinstance(records, list) or not records:
        raise ValueError("evidence bundle requires records")
    for index, raw_record in enumerate(records):
        record = _require_object(raw_record, f"records[{index}]")
        record_group = record.get("evidence_group")
        if record_group in _ALLOWED_GROUPS and record_group != group:
            raise ValueError("vulnerable/fixed/safe/unrelated/unknown evidence groups cannot be mixed")
        if record_group != group:
            raise ValueError("evidence record group must match its bundle")
        _require_id(record.get("evidence_id"), f"records[{index}].evidence_id")
        _require_id(record.get("case_id"), f"records[{index}].case_id")
        _require_id(record.get("run_id"), f"records[{index}].run_id")
        _validate_binding(record, prefix=f"records[{index}]")
    return data


def validate_label_release(
    label_release: Any,
    design_manifest: Mapping[str, Any],
) -> Mapping[str, Any]:
    validate_design_manifest(design_manifest)
    data = _require_object(label_release, "label release")
    if design_manifest.get("status") != "labels_revealed":
        raise ValueError("labels can only be validated after the prediction is sealed")
    if data.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported label release schema_version")
    if data.get("holdout_id") != design_manifest["holdout_id"]:
        raise ValueError("label release holdout_id mismatch")
    _require_sha256(data.get("prediction_sha256"), "label_release.prediction_sha256")
    if data.get("prediction_sha256") != design_manifest.get("prediction_sha256"):
        raise ValueError("label release prediction hash mismatch")
    if canonical_sha256(data) != design_manifest.get("label_release_sha256"):
        raise ValueError("label release artifact hash mismatch")
    labels = data.get("labels")
    if not isinstance(labels, list):
        raise ValueError("label release requires labels")
    expected = {item["case_id"]: item["stratum"] for item in design_manifest["cases"]}
    seen = set()
    for index, raw_label in enumerate(labels):
        label = _require_object(raw_label, f"labels[{index}]")
        case_id = label.get("case_id")
        if case_id not in expected or case_id in seen:
            raise ValueError("label case_id is unknown or duplicated")
        seen.add(case_id)
        group = label.get("evidence_group")
        if group != _STRATUM_GROUP[expected[case_id]]:
            raise ValueError("label evidence group does not match the predeclared stratum")
        _require_sha256(label.get("label_artifact_sha256"), f"labels[{index}].label_artifact_sha256")
    if seen != set(expected):
        raise ValueError("label release must cover every holdout case")
    bundles = data.get("evidence_bundles")
    if not isinstance(bundles, list) or not bundles:
        raise ValueError("label release requires evidence bundles")
    expected_binding = {
        item["case_id"]: {
            field: item[field]
            for field in (
                "repository",
                "commit",
                "path",
                "source_sha256",
                "snapshot_sha256",
                "profile_id",
                "tool_id",
                "tool_version",
            )
        }
        for item in design_manifest["cases"]
    }
    bundled_cases = set()
    for bundle in bundles:
        validated = validate_evidence_bundle(bundle)
        for record in validated["records"]:
            case_id = record["case_id"]
            if case_id not in expected_binding or case_id in bundled_cases:
                raise ValueError("evidence bundle case is unknown or duplicated")
            bundled_cases.add(case_id)
            actual_binding = {
                field: record[field]
                for field in expected_binding[case_id]
            }
            if actual_binding != expected_binding[case_id]:
                raise ValueError("evidence binding does not match the frozen holdout case")
    if bundled_cases != set(expected_binding):
        raise ValueError("evidence bundles must cover every holdout case")
    return data


def verify_source_artifacts(
    design_manifest: Mapping[str, Any],
    source_roots: Mapping[str, Path],
    *,
    verify_git_head: bool = True,
) -> None:
    validate_design_manifest(design_manifest)
    commits = {item["commit"] for item in design_manifest["cases"]}
    if set(source_roots) != commits:
        raise ValueError("each pinned holdout commit needs one external source root")
    roots = {}
    for commit, source_root in source_roots.items():
        root = Path(source_root).resolve()
        if not root.is_dir():
            raise ValueError("source root must be an existing directory")
        if verify_git_head:
            process = subprocess.run(
                ["git", "-C", str(root), "rev-parse", "HEAD"],
                text=True,
                capture_output=True,
                check=False,
            )
            if process.returncode != 0:
                raise ValueError("source root is not a verified Git checkout")
            if process.stdout.strip() != commit:
                raise ValueError("source root HEAD does not match its pinned holdout commit")
        roots[commit] = root
    for case in design_manifest["cases"]:
        root = roots[case["commit"]]
        path = (root / case["path"]).resolve()
        if not path.is_relative_to(root):
            raise ValueError("holdout source path escapes source root")
        if not path.is_file():
            raise ValueError("holdout source artifact is missing")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != case["source_sha256"]:
            raise ValueError("holdout source hash mismatch")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate-design")
    validate.add_argument("manifest", type=Path)

    hash_prediction = subparsers.add_parser("hash-prediction")
    hash_prediction.add_argument("manifest", type=Path)
    hash_prediction.add_argument("prediction", type=Path)

    labels = subparsers.add_parser("validate-label-release")
    labels.add_argument("manifest", type=Path)
    labels.add_argument("label_release", type=Path)

    sources = subparsers.add_parser("verify-sources")
    sources.add_argument("manifest", type=Path)
    sources.add_argument(
        "--source-root",
        action="append",
        required=True,
        metavar="COMMIT=PATH",
        help="repeat once for every pinned holdout commit",
    )
    sources.add_argument("--skip-git-head-check", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    design = json.loads(args.manifest.read_text(encoding="utf-8"))
    if args.command == "validate-design":
        validate_design_manifest(design)
        print(f"[OK] holdout design {design['holdout_id']} is {design['status']}")
        return 0
    if args.command == "hash-prediction":
        prediction = json.loads(args.prediction.read_text(encoding="utf-8"))
        validate_prediction_manifest(prediction, design)
        digest = canonical_sha256(prediction)
        print(digest)
        return 0
    if args.command == "validate-label-release":
        labels = json.loads(args.label_release.read_text(encoding="utf-8"))
        validate_label_release(labels, design)
        print(f"[OK] label release is bound to prediction {labels['prediction_sha256']}")
        return 0
    source_roots = {}
    for item in args.source_root:
        commit, separator, raw_path = item.partition("=")
        if not separator or not _COMMIT_RE.fullmatch(commit) or not raw_path:
            raise SystemExit("--source-root must use COMMIT=PATH")
        if commit in source_roots:
            raise SystemExit("--source-root commit is duplicated")
        source_roots[commit] = Path(raw_path)
    verify_source_artifacts(
        design,
        source_roots,
        verify_git_head=not args.skip_git_head_check,
    )
    print("[OK] external holdout source artifacts match")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
