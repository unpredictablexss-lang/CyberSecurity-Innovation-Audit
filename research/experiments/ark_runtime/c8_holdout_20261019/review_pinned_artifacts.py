"""Audit pinned remote holdout artifacts against the 0.7.0 rule-freeze gate.

This script reads Git objects only. It never fetches, checks out, resets, pushes,
or overwrites the pinned packet artifacts. Outputs use new review-only filenames.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[4]
REF = "origin/codex/c-line-ark-runtime-replay-20261019"
EXPECTED_VERSION = "0.7.0"
EXPECTED_RULES = (
    "ark.runtime.typedarray-store-type-origin",
    "ark.runtime.typedarray-allocation-exception-guard",
)
FREEZE_PATH = "research/deliveries/cpp/ark-runtime-c-line-algorithm-freeze-20261018.json"
OBSERVED_PATH = "research/deliveries/cpp/C_LINE_FREEZE_OBSERVED_20261019.json"
LEDGER_PATH = "research/deliveries/cpp/coverage_ledger_20261019.json"
PACKETS = (
    "research/deliveries/cpp/holdout-arkcompiler-runtime-core-a053abc4",
    "research/deliveries/cpp/holdout-arkcompiler-ets-frontend-fadba67",
)


def git(*args: str, text: bool = False) -> bytes | str:
    data = subprocess.check_output(["git", "-C", str(ROOT), *args])
    return data.decode("utf-8-sig") if text else data


def remote_bytes(path: str) -> bytes:
    return git("show", f"{REF}:{path}")


def remote_text(path: str) -> str:
    return remote_bytes(path).decode("utf-8-sig")


def remote_json(path: str) -> Any:
    return json.loads(remote_text(path))


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def blob_and_sha(path: str) -> dict[str, Any]:
    data = remote_bytes(path)
    return {
        "path": path,
        "git_blob": git("rev-parse", f"{REF}:{path}", text=True).strip(),
        "bytes": len(data),
        "sha256": sha256(data),
    }


def object_status(object_id: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(ROOT), "cat-file", "-e", object_id],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return "available" if result.returncode == 0 else "missing"


def nested_keys(value: Any) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {key for child in value.values() for key in nested_keys(child)}
    if isinstance(value, list):
        return {key for child in value for key in nested_keys(child)}
    return set()


def packet_review(base: str) -> dict[str, Any]:
    manifest_path = f"{base}/blind_manifest.json"
    labels_path = f"{base}/reviewer_labels.csv"
    packet_path = f"{base}/blind_packet.md"
    prepare_path = f"{base}/prepare_blind_review.py"
    manifest = remote_json(manifest_path)
    rows = list(csv.DictReader(io.StringIO(remote_text(labels_path))))
    label_columns = [name for name in (rows[0].keys() if rows else ()) if name != "sample_id"]
    nonempty_label_cells = sum(
        bool((row.get(name) or "").strip()) for row in rows for name in label_columns
    )
    samples = manifest.get("samples", [])
    additional = manifest.get("selection", {}).get("additional_samples", [])
    forbidden_keys = {
        "label", "truth", "expected_label", "prediction", "detector_result", "verdict"
    }
    sample_records = samples + additional
    leaked_keys = sorted({
        key for record in sample_records for key in record if key.lower() in forbidden_keys
    })
    timing_columns = [name for name in label_columns if name in {"active_seconds", "paused_seconds"}]
    review_fields = set(label_columns)
    missing_review_fields = sorted(
        {"reviewer_id", "reviewed_at", "confidence", "active_seconds", "paused_seconds",
         "adjudication_status", "disagreement_type"} - review_fields
    )
    source = manifest.get("source", {})
    source_binding = {
        key: source.get(key)
        for key in ("repository", "commit", "tree", "git_blob", "blob_oid", "path", "sha256")
        if key in source
    }
    source_binding["git_object_status"] = {
        key: object_status(str(source[key]))
        for key in ("commit", "tree", "git_blob", "blob_oid")
        if source.get(key)
    }
    return {
        "base": base,
        "artifacts": [blob_and_sha(path) for path in
                      (manifest_path, packet_path, labels_path, prepare_path)],
        "schema": manifest.get("schema"),
        "algorithm_freeze": manifest.get("algorithm_freeze"),
        "algorithm_freeze_reference": manifest.get("algorithm_freeze"),
        "source_binding": source_binding,
        "sample_count_manifest": len(samples),
        "sample_count_selection_additional": len(additional),
        "sample_id_count": len(rows),
        "sample_ids_unique": len({row["sample_id"] for row in rows}) == len(rows),
        "sample_ids_match_manifest_samples": [row["sample_id"] for row in rows] ==
                                             [sample.get("sample_id") for sample in samples],
        "blindness": {
            "detector_prediction_or_truth_keys_in_visible_records": leaked_keys,
            "blank_label_cells": nonempty_label_cells == 0,
            "nonempty_label_cells": nonempty_label_cells,
            "packet_file_sha256": sha256(remote_bytes(packet_path)),
        },
        "label_template": {
            "columns": label_columns,
            "missing_required_fields": missing_review_fields,
            "timing_columns_present": timing_columns,
            "reviewer_identity_column_present": "reviewer_id" in review_fields,
            "confidence_column_present": "confidence" in review_fields,
            "adjudication_fields_present": bool(
                {"adjudication_status", "disagreement_type"} & review_fields
            ),
        },
        "metrics_gate": {
            "eligible_for_metrics": False,
            "reason": "No independent completed truth labels; packet strata are not a reliable labelled truth set.",
            "precision": None,
            "recall": None,
            "tp": None,
            "fp": None,
            "fn": None,
            "tn": None,
        },
    }


def main() -> None:
    sys.path.insert(0, str(ROOT))
    from src.ohscanner.detectors.ark_runtime.model import (
        AnalysisBudget,
        DETECTOR_ID,
        EXCEPTION_GUARD_RULE_ID,
        RULE_ID,
        RuntimeTypeModel,
        VERSION,
    )

    source_paths = sorted((ROOT / "src/ohscanner/detectors/ark_runtime").glob("*.py"))
    current_sources = {
        path.relative_to(ROOT).as_posix(): sha256(path.read_bytes()) for path in source_paths
    }
    model = RuntimeTypeModel()
    budget = AnalysisBudget()
    expected_freeze = {
        "schema": "ark-runtime-rule-freeze-requirements-v1",
        "status": "review_reference_only_not_an_execution_result",
        "base_commit": git("rev-parse", "HEAD", text=True).strip(),
        "base_tree": git("rev-parse", "HEAD^{tree}", text=True).strip(),
        "detector_id": DETECTOR_ID,
        "rule_version": VERSION,
        "rule_ids": [RULE_ID, EXCEPTION_GUARD_RULE_ID],
        "model_digest": model.digest,
        "build_profile": model.build_profile,
        "resource_limits": vars(budget),
        "implementation_sha256": current_sources,
        "freeze_policy": {
            "tuning_after_freeze_forbidden": True,
            "historical_verdicts_consumed": False,
            "external_scanner_dependency": False,
            "public_schema_runner_catalog_changes": False,
        },
        "evidence_gate": {
            "default_status": "candidate/unassessed",
            "validated_vulnerability": 0,
            "confirmed_reportable": 0,
            "eligible_for_metrics": False,
            "precision": None,
            "recall": None,
        },
    }
    expected_path = ROOT / "research/methods/ark_runtime/rule_freeze_0.7.0/expected_rule_freeze_0.7.0.json"
    expected_path.write_text(
        json.dumps(expected_freeze, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8", newline="\n",
    )

    freeze = remote_json(FREEZE_PATH)
    observed = remote_json(OBSERVED_PATH)
    ledger = remote_json(LEDGER_PATH)
    freeze_file_sha = sha256(remote_bytes(FREEZE_PATH))
    implementation_checks = {}
    for path, expected in freeze.get("implementation_sha256", {}).items():
        try:
            actual = sha256(remote_bytes(path))
            implementation_checks[path] = {
                "status": "match" if actual == expected else "mismatch",
                "expected": expected,
                "actual": actual,
            }
        except subprocess.CalledProcessError:
            implementation_checks[path] = {
                "status": "missing", "expected": expected, "actual": None
            }

    packet_reviews = [packet_review(base) for base in PACKETS]
    referenced_freeze_hashes = {
        review["algorithm_freeze"].get("freeze_manifest_sha256")
        for review in packet_reviews
        if isinstance(review["algorithm_freeze"], dict)
        and review["algorithm_freeze"].get("freeze_manifest_sha256")
    }
    remote_ark_source_present = True
    try:
        remote_bytes("src/ohscanner/detectors/ark_runtime/model.py")
    except subprocess.CalledProcessError:
        remote_ark_source_present = False

    criteria = [
        {
            "id": "rule_version_and_scope",
            "required": f"{EXPECTED_VERSION} including {', '.join(EXPECTED_RULES)}",
            "observed": f"{freeze.get('detector_version')} including {freeze.get('rule_id')}",
            "status": "gap",
        },
        {
            "id": "implementation_hash_self_consistency",
            "required": "all frozen implementation SHA-256 values match the pinned implementation paths",
            "observed": implementation_checks,
            "status": "pass" if all(item["status"] == "match"
                                   for item in implementation_checks.values()) else "gap",
        },
        {
            "id": "freeze_manifest_digest_binding",
            "required": "packet freeze_manifest_sha256 resolves unambiguously to the pinned freeze manifest",
            "observed": {
                "freeze_manifest_file_sha256": freeze_file_sha,
                "packet_referenced_hashes": sorted(referenced_freeze_hashes),
            },
            "status": "pass" if referenced_freeze_hashes == {freeze_file_sha} else "gap",
        },
        {
            "id": "current_0_7_0_source_binding",
            "required": "rule freeze binds the 0.7.0 src/ohscanner/detectors/ark_runtime files in this base",
            "observed": {
                "remote_ref_contains_current_ark_source": remote_ark_source_present,
                "current_source_sha256": current_sources,
                "current_model_digest": model.digest,
            },
            "status": "pass" if remote_ark_source_present else "gap",
        },
        {
            "id": "profile_and_resource_limits",
            "required": "build profile and AnalysisBudget limits are frozen explicitly",
            "observed": {
                "freeze_keys": sorted(freeze),
                "expected_profile": model.build_profile,
                "expected_limits": vars(budget),
            },
            "status": "gap",
        },
        {
            "id": "blind_packets_and_blank_labels",
            "required": "visible packets contain no predictions/truth and reviewer label cells start blank",
            "observed": [
                {
                    "base": review["base"],
                    "leaked_keys": review["blindness"][
                        "detector_prediction_or_truth_keys_in_visible_records"],
                    "blank_label_cells": review["blindness"]["blank_label_cells"],
                }
                for review in packet_reviews
            ],
            "status": "pass" if all(
                not review["blindness"]["detector_prediction_or_truth_keys_in_visible_records"]
                and review["blindness"]["blank_label_cells"]
                for review in packet_reviews
            ) else "gap",
        },
        {
            "id": "independent_truth",
            "required": "independent reliable labels completed for a true holdout",
            "observed": "runtime-core explicitly not independent; frontend is applicability-only; all label cells blank",
            "status": "gap",
        },
        {
            "id": "reviewer_timing_and_adjudication_schema",
            "required": "reviewer identity/confidence, active/paused timing, disagreement and adjudication fields",
            "observed": [review["label_template"] for review in packet_reviews],
            "status": "gap",
        },
        {
            "id": "metrics_disabled",
            "required": "no Precision/Recall/TP/FP/FN/TN before reliable independent truth",
            "observed": {
                "eligible_for_metrics": False,
                "precision": None,
                "recall": None,
                "tp": None,
                "fp": None,
                "fn": None,
                "tn": None,
            },
            "status": "pass",
        },
        {
            "id": "coverage_performance_fields",
            "required": "coverage/partial/unknown plus wall/RSS/Token/cost fields",
            "observed": {
                "coverage_ledger_lane": ledger.get("lane"),
                "coverage_ledger_keys": sorted(ledger),
                "performance_fields_present": sorted(
                    nested_keys(ledger) & {"wall", "wall_seconds", "rss", "rss_kib",
                                           "token", "tokens", "cost", "cost_usd"}
                ),
            },
            "status": "gap",
        },
    ]

    missing_items = [
        {
            "id": "M01",
            "priority": 1,
            "item": "Publish a non-overwriting 0.7.0 rule-freeze manifest for both Ark rules and the current eight source files.",
            "acceptance": "rule version 0.7.0, both rule IDs, current source SHA-256 values, model digest, build profile and AnalysisBudget limits are bound.",
        },
        {
            "id": "M02",
            "priority": 1,
            "item": "Resolve the freeze_manifest_sha256 mismatch/unexplained digest convention.",
            "acceptance": "each packet reference hashes the exact pinned freeze manifest bytes or documents and reproduces a canonicalization algorithm.",
        },
        {
            "id": "M03",
            "priority": 1,
            "item": "Repair frozen implementation self-consistency without rewriting historical packets.",
            "acceptance": "all implementation_sha256 entries match their pinned path bytes at the reviewed ref, or a separate immutable implementation snapshot is added.",
        },
        {
            "id": "M04",
            "priority": 1,
            "item": "Obtain independent reviewer labels for a true unseen holdout.",
            "acceptance": "at least two independent reviewers label every eligible case; the author/developer is not the truth authority.",
        },
        {
            "id": "M05",
            "priority": 2,
            "item": "Add a separate reviewer metadata/timing extension rather than editing pinned CSVs.",
            "acceptance": "reviewer_id, reviewed_at, confidence, active_seconds, paused_seconds, unknown_reason and evidence are complete.",
        },
        {
            "id": "M06",
            "priority": 2,
            "item": "Add disagreement and adjudication ledger.",
            "acceptance": "all disagreements are retained, adjudicator identity/basis is recorded, and unresolved cases stay unknown.",
        },
        {
            "id": "M07",
            "priority": 2,
            "item": "Record exact replay argv/env and performance for the frozen 0.7.0 packet run.",
            "acceptance": "coverage/partial/unknown, wall, RSS, Token and cost fields are present with unknown explicitly stated when not measured.",
        },
        {
            "id": "M08",
            "priority": 3,
            "item": "Acquire missing upstream commit/tree/creator objects in a local pinned store or keep source replay blocked.",
            "acceptance": "no missing object is converted to safe/miss; unavailable objects remain unknown/blocked.",
        },
    ]

    result = {
        "schema": "ark-runtime-pinned-artifact-gap-matrix-v1",
        "date": "2026-10-19",
        "reviewed_ref": {
            "ref": REF,
            "commit": git("rev-parse", REF, text=True).strip(),
            "tree": git("rev-parse", f"{REF}^{{tree}}", text=True).strip(),
        },
        "base": {
            "commit": git("rev-parse", "HEAD", text=True).strip(),
            "tree": git("rev-parse", "HEAD^{tree}", text=True).strip(),
        },
        "reviewed_artifacts": [blob_and_sha(path) for path in
                               (FREEZE_PATH, OBSERVED_PATH, LEDGER_PATH)],
        "expected_rule_freeze": {
            "path": "research/methods/ark_runtime/rule_freeze_0.7.0/expected_rule_freeze_0.7.0.json",
            "rule_version": EXPECTED_VERSION,
            "rule_ids": list(EXPECTED_RULES),
            "model_digest": model.digest,
            "implementation_sha256": current_sources,
            "build_profile": model.build_profile,
            "resource_limits": vars(budget),
        },
        "remote_freeze_observed": {
            "detector_version": freeze.get("detector_version"),
            "rule_id": freeze.get("rule_id"),
            "model_sha256": freeze.get("model_sha256"),
            "implementation_checks": implementation_checks,
            "freeze_manifest_file_sha256": freeze_file_sha,
            "packet_referenced_freeze_hashes": sorted(referenced_freeze_hashes),
            "source_profiles": freeze.get("source_profiles"),
            "source_profile_object_status": [
                {
                    "repository": profile.get("repository"),
                    "objects": {
                        key: object_status(str(profile[key]))
                        for key in ("commit", "tree", "target_blob", "creator_blob")
                        if profile.get(key)
                    },
                }
                for profile in freeze.get("source_profiles", [])
            ],
        },
        "packets": packet_reviews,
        "criteria": criteria,
        "missing_items": missing_items,
        "metrics_gate": {
            "eligible_for_metrics": False,
            "precision": None,
            "recall": None,
            "zero_fp_fn_claim_allowed": False,
            "product_cia_cve_or_confirmed_claim_allowed": False,
            "validated_vulnerability": 0,
        },
        "limitations": [
            "This is a pinned-artifact audit only; no remote file was overwritten.",
            "Runtime-core was inspected before freeze and is not an independent holdout.",
            "ETS Frontend is an applicability/false-match frame, not a reliable semantic recall truth set.",
            "Blank labels, partial parse and missing Git objects remain unknown/partial rather than safe or miss.",
        ],
    }
    output = ROOT / "research/experiments/ark_runtime/c8_holdout_20261019/remote_artifact_gap_matrix_20261019.json"
    output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8", newline="\n",
    )
    print(json.dumps({
        "output": output.relative_to(ROOT).as_posix(),
        "criteria": {item["id"]: item["status"] for item in criteria},
        "missing_items": len(missing_items),
        "eligible_for_metrics": False,
    }, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
