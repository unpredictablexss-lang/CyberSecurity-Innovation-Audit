#!/usr/bin/env python3
"""Generate Ark product-closure status from the fail-closed profile manifest."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def canonical_hash_payload(value: Any) -> str:
    import hashlib
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile-manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    profile = json.loads(args.profile_manifest.read_text(encoding="utf-8"))
    cases = []
    for item in profile.get("cases", []):
        cases.append({
            "case_id": item.get("case_id"),
            "component": item.get("component"),
            "evidence_class": item.get("evidence_class"),
            "source_identity_status": item.get("source_identity_status"),
            "build_profile_status": item.get("build_profile", {}).get("status"),
            "preprocess_profile_status": item.get("preprocess_profile", {}).get("status"),
            "product_association": item.get("product_association"),
            "security_obligations": {
                "product_build_and_version": "unknown",
                "real_entry_point": "unknown",
                "permission_or_trust_boundary": "unknown",
                "attacker_control": "unknown",
                "trigger_conditions": "unknown",
                "reachable_sensitive_operation": "unknown",
                "concrete_cia_impact": "unknown",
                "authorized_isolated_poc": "not_run",
                "fix_patch_identity": "partial_or_unknown",
                "fixed_product_revalidation": "not_run",
            },
            "admission": {
                "decision": "NOT_ADMITTED",
                "validated_vulnerability": False,
                "reason": "At least product build/entry/permission/trigger/CIA/PoC/fixed-product revalidation remains missing.",
            },
            "minimal_remediation": [
                "Lock exact product manifest, version, branch and shipped binary/source mapping.",
                "Capture exact args.gn/GN target, compile commands, include closure and preprocessed TU hashes.",
                "Prove realistic entry/privilege boundary, attacker-controlled trigger and reachable sensitive operation.",
                "Run authorized isolated PoC on vulnerable product build and preserve deterministic logs/artifacts.",
                "Apply the exact fix, rebuild the same product profile, rerun the PoC and regression controls.",
            ],
        })
    matrix = {
        "schema": "ohscanner.ark-product-closure-matrix/v1",
        "status": "BLOCKED",
        "decision": "NOT_ADMITTED",
        "profile_payload_sha256": profile.get("payload_sha256"),
        "case_count": len(cases),
        "cases": cases,
        "metrics": {"precision": None, "recall": None, "reason": "no independent reliable labelled holdout; owner waived reviewer staffing prerequisite, but no review ran and no metrics are available"},
    }
    matrix["payload_sha256"] = canonical_hash_payload(matrix)
    task_tree = {
        "schema": "ohscanner.g12-pc-task-tree/v1",
        "root": "G12-PC-PRODUCT-ADMISSION-CLOSURE",
        "status": "ACTIVE_NOT_ADMITTED",
        "nodes": [
            {"id": "G12-PC-1", "title": "Ark parent/fix build and preprocess profile", "status": "IN_PROGRESS_BLOCKED", "next": "Bind official Ark Git store and exact product build/preprocess artifacts."},
            {"id": "G12-PC-2", "title": "Independent holdout freeze and double-blind adjudication", "status": "WAIVED_BY_OWNER_NOT_EXECUTED", "next": "Owner waived the human-review prerequisite for this decision; do not claim evaluation pass or compute metrics without reliable independent human labels."},
            {"id": "G12-PC-3", "title": "Candidate product applicability closure", "status": "BLOCKED", "next": "Close entry, permission, trigger, attacker control and CIA impact per case."},
            {"id": "G12-PC-4", "title": "Authorized isolated PoC", "status": "NOT_RUN", "next": "Execute only after product build and authorization gates are locked."},
            {"id": "G12-PC-5", "title": "Fix and fixed-product revalidation", "status": "NOT_RUN", "next": "Patch, rebuild same profile, replay PoC and controls."},
            {"id": "G12-PC-6", "title": "Competition admission", "status": "NOT_ADMITTED", "next": "Re-evaluate only after all mandatory evidence gates close."},
        ],
    }
    task_tree["payload_sha256"] = canonical_hash_payload(task_tree)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "product_closure_matrix.json").write_text(json.dumps(matrix, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    (args.output_dir / "task_tree.json").write_text(json.dumps(task_tree, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "BLOCKED", "case_count": len(cases), "decision": "NOT_ADMITTED"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
