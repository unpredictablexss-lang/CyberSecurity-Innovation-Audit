#!/usr/bin/env python3
"""Generate non-blocking development tasks and an honest product-evidence inventory."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def canonical_hash_payload(value: Any) -> str:
    import hashlib
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def development_task_tree() -> dict[str, Any]:
    """Keep optional product/evaluation work out of development dependencies."""
    tree = {
        "schema": "ohscanner.g12-pc-task-tree/v1",
        "root": "G12-PC-PRODUCT-ADMISSION-CLOSURE",
        "status": "ACTIVE_DEVELOPMENT",
        "authorization": "config/collaboration/standing_authorization.json",
        "blocking_prerequisites": [],
        "completion_rule": "Deliver a concrete change, relevant tests and available evidence; optional product/evaluation work does not block completion.",
        "nodes": [
            {"id": "G12-PC-1", "title": "Available source/build profile investigation", "status": "OPTIONAL_AVAILABLE_INPUTS", "blocks_development": False, "next": "Find available public/local source and build inputs autonomously; record missing product fields as unknown and continue source/component work."},
            {"id": "G12-PC-2", "title": "Optional formal evaluation", "status": "OPTIONAL_NOT_RUN", "blocks_development": False, "evidence_status": "NOT_RUN", "next": "Use existing cases for development regression now. Formal holdout and human staffing are optional; do not invent labels or accuracy metrics."},
            {"id": "G12-PC-3", "title": "Optional product applicability", "status": "OPTIONAL_AVAILABLE_INPUTS", "blocks_development": False, "evidence_status": "UNKNOWN", "next": "Report source/component findings now; investigate actual products only when suitable inputs exist."},
            {"id": "G12-PC-4", "title": "Local isolated component PoC", "status": "READY_WITH_AVAILABLE_ENVIRONMENT", "blocks_development": False, "evidence_status": "NOT_RUN", "next": "Standing authorization applies. Select a reproducible component/version and isolated environment; build and test without waiting for product proof or another approval."},
            {"id": "G12-PC-5", "title": "Per-case fix and regression", "status": "READY_PER_CASE", "blocks_development": False, "evidence_status": "NOT_RUN", "next": "Test the affected/fixed component pair when available; no portfolio-wide or shipped-product prerequisite."},
            {"id": "G12-PC-6", "title": "Incremental evidence report", "status": "READY_FOR_EVIDENCE_REPORT", "blocks_development": False, "next": "Deliver supported source/component results and limitations now; no all-case, staffing or product-admission gate."},
        ],
    }
    tree["payload_sha256"] = canonical_hash_payload(tree)
    return tree


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
                "decision": "PRODUCT_NOT_ASSESSED",
                "validated_vulnerability": False,
                "blocks_development": False,
                "reason": "Product evidence remains unknown; source/component development, PoCs and reports are authorized independently.",
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
        "status": "EVIDENCE_INVENTORY",
        "decision": "REPORT_AVAILABLE_EVIDENCE",
        "blocks_development": False,
        "profile_payload_sha256": profile.get("payload_sha256"),
        "case_count": len(cases),
        "cases": cases,
        "metrics": {"precision": None, "recall": None, "reason": "no independent reliable labelled holdout"},
    }
    matrix["payload_sha256"] = canonical_hash_payload(matrix)
    task_tree = development_task_tree()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "product_closure_matrix.json").write_text(json.dumps(matrix, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    (args.output_dir / "task_tree.json").write_text(json.dumps(task_tree, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": task_tree["status"], "case_count": len(cases), "decision": matrix["decision"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
