#!/usr/bin/env python3
"""Preflight a real independent holdout before any labels are opened."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

PREREG_SCHEMA = "ohscanner.ark-holdout-preregistration/v1"
LEAKAGE_SCHEMA = "ohscanner.ark-holdout-leakage-ledger/v1"
INTAKE_SCHEMA = "ohscanner.ark-holdout-intake/v1"
GOVERNANCE_SCHEMA = "ohscanner.ark-holdout-governance/v1"
RESULT_SCHEMA = "ohscanner.ark-holdout-preflight/v1"
HEX256 = re.compile(r"^[0-9a-f]{64}$")


def canonical_hash(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def emit_templates(directory: Path, count: int) -> None:
    prereg = {
        "schema": PREREG_SCHEMA,
        "status": "TEMPLATE_NOT_FROZEN",
        "sampling_frame_sha256": "0" * 64,
        "family_split_sha256": "0" * 64,
        "development_exclusion_sha256": "0" * 64,
        "sample_size": count,
        "split_unit": "root_cause_or_patch_family",
        "labels": ["vulnerable_shape", "not_vulnerable_shape", "unknown"],
        "metrics": ["family_level_TP", "FP", "FN", "TN", "unknown"],
        "precision_recall_rule": "only after reliable independent human adjudicated truth",
    }
    leakage = {
        "schema": LEAKAGE_SCHEMA,
        "status": "TEMPLATE_NOT_FROZEN",
        "development_artifacts": [],
    }
    governance = {
        "schema": GOVERNANCE_SCHEMA,
        "status": "TEMPLATE_NOT_SIGNED",
        "reviewers": [
            {"reviewer_id": "reviewer-a", "independent_human": True, "model_generated": False, "rule_author": False},
            {"reviewer_id": "reviewer-b", "independent_human": True, "model_generated": False, "rule_author": False},
        ],
        "adjudicator": {"reviewer_id": "adjudicator", "independent_human": True, "model_generated": False, "rule_author": False},
        "truth_custodian": {"reviewer_id": "truth-custodian", "independent_human": True, "model_generated": False, "rule_author": False},
        "truth_state": "sealed_not_opened_by_reviewers",
    }
    directory.mkdir(parents=True, exist_ok=True)
    for name, value in (
        ("preregistration.template.json", prereg),
        ("leakage_ledger.template.json", leakage),
        ("governance.template.json", governance),
    ):
        (directory / name).write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def evaluate(prereg: dict[str, Any], leakage: dict[str, Any], intake: dict[str, Any], governance: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    if prereg.get("schema") != PREREG_SCHEMA:
        errors.append("prereg_schema")
    if leakage.get("schema") != LEAKAGE_SCHEMA:
        errors.append("leakage_schema")
    if intake.get("schema") != INTAKE_SCHEMA:
        errors.append("intake_schema")
    if governance.get("schema") != GOVERNANCE_SCHEMA:
        errors.append("governance_schema")
    if prereg.get("status") != "FROZEN":
        errors.append("preregistration_not_frozen")
    if leakage.get("status") != "FROZEN":
        errors.append("leakage_ledger_not_frozen")
    if governance.get("status") != "SIGNED_INDEPENDENT_ROLES":
        errors.append("governance_not_signed")
    for field in ("sampling_frame_sha256", "family_split_sha256", "development_exclusion_sha256"):
        value = prereg.get(field)
        if not isinstance(value, str) or not HEX256.fullmatch(value) or set(value) == {"0"}:
            errors.append(f"invalid_prereg_hash:{field}")
    cases = intake.get("cases", [])
    if prereg.get("sample_size") != len(cases) or not cases:
        errors.append("sample_size_mismatch_or_empty")
    if intake.get("preregistration_sha256") != canonical_hash(prereg):
        errors.append("intake_preregistration_hash_mismatch")
    if intake.get("development_leakage_ledger_sha256") != canonical_hash(leakage):
        errors.append("intake_leakage_hash_mismatch")

    development_hashes = {item.get("source_sha256") for item in leakage.get("development_artifacts", []) if item.get("source_sha256")}
    development_families = {item.get("family_id") for item in leakage.get("development_artifacts", []) if item.get("family_id")}
    for case in cases:
        case_id = case.get("case_id")
        if case.get("development_overlap") is not False:
            errors.append(f"development_overlap:{case_id}")
        if case.get("source_sha256") in development_hashes:
            errors.append(f"source_hash_leakage:{case_id}")
        if case.get("family_id") in development_families:
            errors.append(f"family_leakage:{case_id}")
        if case.get("sampling_frame_sha256") != prereg.get("sampling_frame_sha256"):
            errors.append(f"sampling_frame_mismatch:{case_id}")

    reviewers = governance.get("reviewers", [])
    ids = [item.get("reviewer_id") for item in reviewers]
    if len(reviewers) < 2 or len(ids) != len(set(ids)):
        errors.append("reviewer_identity_invalid")
    adjudicator_id = governance.get("adjudicator", {}).get("reviewer_id")
    custodian_id = governance.get("truth_custodian", {}).get("reviewer_id")
    if adjudicator_id in ids or custodian_id in ids or adjudicator_id == custodian_id:
        errors.append("role_separation_violation")
    roles = reviewers + [governance.get("adjudicator", {}), governance.get("truth_custodian", {})]
    for item in roles:
        if item.get("independent_human") is not True or item.get("model_generated") is not False or item.get("rule_author") is not False:
            errors.append(f"invalid_role:{item.get('reviewer_id')}")
    if governance.get("truth_state") != "sealed_not_opened_by_reviewers":
        errors.append("truth_not_sealed")

    status = "READY_FOR_FREEZE" if not errors else "BLOCKED"
    result = {
        "schema": RESULT_SCHEMA,
        "status": status,
        "case_count": len(cases),
        "reviewer_count": len(reviewers),
        "development_artifact_count": len(leakage.get("development_artifacts", [])),
        "decision": "PROCEED_TO_DOUBLE_BLIND_FREEZE" if status == "READY_FOR_FREEZE" else "DO_NOT_FREEZE_OR_LABEL",
        "errors": errors,
    }
    result["payload_sha256"] = canonical_hash(result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preregistration", type=Path, required=True)
    parser.add_argument("--leakage-ledger", type=Path, required=True)
    parser.add_argument("--intake", type=Path, required=True)
    parser.add_argument("--governance", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--emit-templates", action="store_true")
    parser.add_argument("--template-dir", type=Path)
    parser.add_argument("--template-case-count", type=int, default=0)
    args = parser.parse_args()
    if args.emit_templates:
        emit_templates(args.template_dir or args.preregistration.parent, args.template_case_count)
        print(json.dumps({"status": "TEMPLATES_WRITTEN"}, indent=2))
        return 0
    result = evaluate(load(args.preregistration), load(args.leakage_ledger), load(args.intake), load(args.governance))
    args.output.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "decision": result["decision"], "errors": len(result["errors"])}, indent=2))
    return 0 if result["status"] == "READY_FOR_FREEZE" else 2


if __name__ == "__main__":
    raise SystemExit(main())