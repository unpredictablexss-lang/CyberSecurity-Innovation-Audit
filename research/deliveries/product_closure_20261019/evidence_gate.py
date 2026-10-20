#!/usr/bin/env python3
"""Gate PoC, fix-revalidation and admission by hashed mandatory product evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA = "ohscanner.g12-pc-case-evidence-bundle/v1"
RESULT_SCHEMA = "ohscanner.g12-pc-evidence-gate/v1"
HEX256 = re.compile(r"^[0-9a-f]{64}$")
POC_REQUIRED = (
    "product_build_and_version",
    "real_entry_point",
    "permission_or_trust_boundary",
    "attacker_control",
    "trigger_conditions",
    "reachable_sensitive_operation",
    "concrete_cia_impact",
    "authorization",
    "isolation",
)
FIX_REQUIRED = (
    "authorized_poc_completed",
    "patch_identity",
    "fixed_product_build_profile",
)
ADMISSION_REQUIRED = (
    "fixed_product_revalidation",
    "independent_holdout_reliable",
    "performance_innovation_complete",
    "final_machine_bundle_complete",
)


def canonical_hash(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def safe_relative(value: str) -> bool:
    path = PurePosixPath(value)
    return bool(value) and not path.is_absolute() and ".." not in path.parts and "\\" not in value


def verify_artifact(value: Any, evidence_root: Path, label: str, errors: list[str]) -> bool:
    if not isinstance(value, dict):
        errors.append(f"evidence_not_object:{label}")
        return False
    rel = value.get("path")
    if not safe_relative(rel or ""):
        errors.append(f"unsafe_evidence_path:{label}")
        return False
    full = evidence_root.joinpath(*PurePosixPath(rel).parts)
    try:
        data = full.read_bytes()
    except OSError:
        errors.append(f"missing_evidence_artifact:{label}")
        return False
    digest = hashlib.sha256(data).hexdigest()
    if value.get("sha256") != digest or not HEX256.fullmatch(value.get("sha256", "")):
        errors.append(f"evidence_sha256_mismatch:{label}")
        return False
    if value.get("bytes") != len(data):
        errors.append(f"evidence_bytes_mismatch:{label}")
        return False
    return True


def is_verified(value: Any, evidence_root: Path, label: str, errors: list[str]) -> bool:
    if not isinstance(value, dict) or value.get("status") != "verified":
        errors.append(f"not_verified:{label}")
        return False
    evidence = value.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        errors.append(f"missing_evidence:{label}")
        return False
    return all(verify_artifact(item, evidence_root, f"{label}:{index}", errors) for index, item in enumerate(evidence))


def is_approved(value: Any, evidence_root: Path, label: str, errors: list[str]) -> bool:
    if not isinstance(value, dict) or value.get("status") != "approved":
        errors.append(f"not_approved:{label}")
        return False
    for field in ("approval_id", "authorizer", "scope", "expires_at"):
        if not value.get(field):
            errors.append(f"missing_approval_field:{label}:{field}")
            return False
    evidence = value.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        errors.append(f"missing_approval_evidence:{label}")
        return False
    return all(verify_artifact(item, evidence_root, f"{label}:{index}", errors) for index, item in enumerate(evidence))


def emit_template(matrix: dict[str, Any], output: Path) -> None:
    fields = POC_REQUIRED + FIX_REQUIRED + ADMISSION_REQUIRED
    template = {
        "schema": SCHEMA,
        "status": "TEMPLATE_NOT_EVIDENCE",
        "cases": {
            item["case_id"]: {
                field: {"status": "unknown", "evidence": [], "limitations": ["evidence not supplied"]}
                for field in fields
            }
            for item in matrix.get("cases", [])
        },
    }
    output.write_text(json.dumps(template, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def evaluate(matrix: dict[str, Any], bundle: dict[str, Any], evidence_root: Path) -> dict[str, Any]:
    errors: list[str] = []
    if bundle.get("schema") != SCHEMA:
        errors.append("bundle_schema_mismatch")
    if bundle.get("status") != "EVIDENCE_COMPLETE":
        errors.append("bundle_status_not_evidence_complete")
    matrix_ids = {item.get("case_id") for item in matrix.get("cases", [])}
    bundle_ids = set(bundle.get("cases", {}))
    if matrix_ids != bundle_ids:
        errors.append("case_set_mismatch")
    rows = []
    for case_id in sorted(matrix_ids):
        item = bundle.get("cases", {}).get(case_id, {})
        states: dict[str, bool] = {}
        for field in POC_REQUIRED + FIX_REQUIRED + ADMISSION_REQUIRED:
            label = f"{case_id}:{field}"
            if field == "authorization":
                states[field] = is_approved(item.get(field), evidence_root, label, errors)
            else:
                states[field] = is_verified(item.get(field), evidence_root, label, errors)
        poc_ready = all(states[field] for field in POC_REQUIRED)
        fix_ready = poc_ready and all(states[field] for field in FIX_REQUIRED)
        admission_ready = fix_ready and all(states[field] for field in ADMISSION_REQUIRED)
        rows.append({
            "case_id": case_id,
            "poc_authorization_status": "ELIGIBLE_FOR_AUTHORIZATION_REVIEW" if poc_ready else "BLOCKED",
            "missing_poc_evidence": [field for field in POC_REQUIRED if not states[field]],
            "fix_revalidation_status": "ELIGIBLE_TO_EXECUTE" if fix_ready else "BLOCKED",
            "missing_fix_evidence": [field for field in FIX_REQUIRED if not states[field]],
            "admission_status": "ELIGIBLE_FOR_FULL_REVIEW" if admission_ready else "NOT_ADMITTED",
            "missing_admission_evidence": [field for field in ADMISSION_REQUIRED if not states[field]],
        })
    result = {
        "schema": RESULT_SCHEMA,
        "status": "COMPLETE",
        "poc_eligible_count": sum(row["poc_authorization_status"].startswith("ELIGIBLE") for row in rows),
        "fix_revalidation_eligible_count": sum(row["fix_revalidation_status"].startswith("ELIGIBLE") for row in rows),
        "admission_eligible_count": sum(row["admission_status"].startswith("ELIGIBLE") for row in rows),
        "decision": "NOT_ADMITTED" if not all(row["admission_status"].startswith("ELIGIBLE") for row in rows) else "ELIGIBLE_FOR_ADMISSION_REVIEW",
        "cases": rows,
        "errors": errors,
    }
    result["payload_sha256"] = canonical_hash(result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--closure-matrix", type=Path, required=True)
    parser.add_argument("--evidence-bundle", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--emit-template", action="store_true")
    args = parser.parse_args()
    matrix = json.loads(args.closure_matrix.read_text(encoding="utf-8"))
    if args.emit_template:
        emit_template(matrix, args.evidence_bundle)
        print(json.dumps({"status": "TEMPLATE_WRITTEN", "case_count": len(matrix.get("cases", []))}, indent=2))
        return 0
    bundle = json.loads(args.evidence_bundle.read_text(encoding="utf-8"))
    evidence_root = (args.evidence_root or args.evidence_bundle.parent).resolve()
    result = evaluate(matrix, bundle, evidence_root)
    args.output.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": result["status"],
        "poc_eligible_count": result["poc_eligible_count"],
        "fix_revalidation_eligible_count": result["fix_revalidation_eligible_count"],
        "admission_eligible_count": result["admission_eligible_count"],
        "decision": result["decision"],
        "error_count": len(result["errors"]),
    }, indent=2))
    return 0 if result["decision"] == "ELIGIBLE_FOR_ADMISSION_REVIEW" else 2


if __name__ == "__main__":
    raise SystemExit(main())