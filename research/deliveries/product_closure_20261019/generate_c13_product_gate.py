#!/usr/bin/env python3
"""Generate the C13 per-candidate product gate audit from pinned local evidence."""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path

BASE = "842948084660207fd64399cfd598ed93e5593dcc"
REVIEW_COMMIT = "e4e0761501a83ac25cc67d04c527eefe9f4a1b50"
REVIEW_BLOB = "dbedea677c8dc70c1b0066c7bc52df27bcff06ea"
REVIEW_BLOB_SHA256 = "732b17b4adba11f1fefb93940859d951e03d35a69987b77a61f9a785eefe1240"
COVERAGE_PATH = "research/experiments/known_vulnerability_coverage_20261019/coverage_table.md"


def canonical_hash(value: object) -> str:
    data = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", *args], text=False)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def parse_review_rows(text: str) -> list[dict[str, str]]:
    rows = []
    for line in text.splitlines():
        if not re.match(r"^\|\s*\d+\s*\|", line):
            continue
        parts = [part.strip() for part in line.strip().strip("|").split("|")]
        if len(parts) != 6:
            continue
        rows.append({
            "index": int(parts[0]),
            "bucket": parts[1],
            "identity": parts[2],
            "c12_disposition": parts[3],
            "target_source_identity": parts[4],
            "replay": parts[5],
        })
    return rows


def source_product_gate(disposition: str) -> dict[str, str]:
    not_applicable = disposition.startswith("not-applicable")
    missing = "not_applicable" if not_applicable else "unknown"
    return {
        "evidence_classification": "not-applicable" if not_applicable else "candidate/unassessed",
        "source_identity": "explicit_unknown" if not not_applicable else "not_applicable",
        "product_build_and_version": missing,
        "real_entry_point": missing,
        "permission_or_trust_boundary": missing,
        "trigger_conditions": missing,
        "reachable_sensitive_operation": missing,
        "concrete_cia_impact": missing,
        "authorized_isolated_poc": "not_run" if not not_applicable else "not_applicable",
        "fixed_product_revalidation": "not_run" if not not_applicable else "not_applicable",
        "admission": "NOT_ADMITTED" if not not_applicable else "NOT_APPLICABLE",
    }


def main() -> int:
    here = Path(__file__).resolve().parent
    root = here.parents[2]
    product_path = here / "product_closure_matrix.json"
    build_path = root / "research/methods/ark_runtime/build_profile_20261019/ark_parent_fix_build_profile_manifest.v1.json"
    product = load_json(product_path)
    build = load_json(build_path)
    coverage = git("show", f"{BASE}:{COVERAGE_PATH}").decode("utf-8")
    review_rows = parse_review_rows(coverage)
    review_blob = git("cat-file", "blob", REVIEW_BLOB)
    review_blob_sha = hashlib.sha256(review_blob).hexdigest()
    if review_blob_sha != REVIEW_BLOB_SHA256:
        raise SystemExit("source review blob hash mismatch")
    tree_lines = git("ls-tree", "-r", "-z", REVIEW_COMMIT).split(b"\0")
    review_path = ""
    for raw_line in tree_lines:
        if REVIEW_BLOB.encode("ascii") in raw_line:
            review_path = raw_line.split(b"\t", 1)[1].decode("utf-8")
            break
    if not review_path:
        raise SystemExit("source review blob path not found in pinned review commit")

    reviewed = []
    for row in review_rows:
        gate = source_product_gate(row["c12_disposition"])
        reviewed.append({**row, "evidence_classification": gate["evidence_classification"], "product_gate": gate})

    ark_cases = []
    for case in product.get("cases", []):
        obligations = case.get("security_obligations", {})
        ark_cases.append({
            "case_id": case.get("case_id"),
            "component": case.get("component"),
            "evidence_class": case.get("evidence_class"),
            "evidence_classification": "candidate/unassessed",
            "source_identity_status": case.get("source_identity_status"),
            "product_build_and_version": obligations.get("product_build_and_version", "unknown"),
            "real_entry_point": obligations.get("real_entry_point", "unknown"),
            "permission_or_trust_boundary": obligations.get("permission_or_trust_boundary", "unknown"),
            "trigger_conditions": obligations.get("trigger_conditions", "unknown"),
            "reachable_sensitive_operation": obligations.get("reachable_sensitive_operation", "unknown"),
            "concrete_cia_impact": obligations.get("concrete_cia_impact", "unknown"),
            "authorized_isolated_poc": obligations.get("authorized_isolated_poc", "not_run"),
            "fixed_product_revalidation": obligations.get("fixed_product_revalidation", "not_run"),
            "fix_patch_identity": obligations.get("fix_patch_identity", "partial_or_unknown"),
            "build_profile_status": case.get("build_profile_status", "BLOCKED"),
            "preprocess_profile_status": case.get("preprocess_profile_status", "BLOCKED"),
            "admission": case.get("admission", {}).get("decision", "NOT_ADMITTED"),
        })

    reviewed_candidates = [row for row in reviewed if row["bucket"] != "exclusion"]
    output = {
        "schema": "ohscanner.c13-candidate-product-gate-audit/v1",
        "status": "BLOCKED",
        "decision": "NOT_ADMITTED",
        "promotion_policy": {
            "default": "candidate/unassessed",
            "confirmed_reportable_requires": [
                "real_entry_point", "permission_or_trust_boundary", "trigger_conditions",
                "reachable_sensitive_operation", "concrete_cia_impact",
                "authorized_isolated_poc", "fixed_product_revalidation",
            ],
            "promoted_to_confirmed_reportable": [],
        },
        "baseline": {
            "commit": BASE,
            "tree": git("rev-parse", f"{BASE}^{{tree}}").decode().strip(),
        },
        "source_review_identity": {
            "path": review_path,
            "blob": REVIEW_BLOB,
            "bytes": len(review_blob),
            "sha256": review_blob_sha,
            "commit": REVIEW_COMMIT,
            "tree": "307ac8237263db793028e0bf34a82a85f60821a5",
        },
        "scanner_coverage_status": {
            "reviewed_dispositions": len(reviewed),
            "candidate_or_explicit_unknown_rows": len(reviewed_candidates),
            "ark_parent_fix_product_candidates": len(ark_cases),
            "focused_regression_command": "python -m unittest -v tests.detectors.ark_runtime.test_c12_deep_semantics tests.detectors.ark_runtime.test_c11_alias_cross_helper tests.detectors.test_known_case_corpus",
            "focused_regression_result": "31 tests passed; see research/deliveries/admission_20261019/C13_validation.txt",
            "interpretation": "regression controls only; not independent recall or product vulnerability proof",
        },
        "build_profile": {
            "manifest_payload_sha256": build.get("payload_sha256"),
            "identity_coverage": build.get("identity_coverage"),
            "global_blockers": build.get("global_blockers"),
        },
        "reviewed_case_dispositions": reviewed,
        "ark_product_candidates": ark_cases,
        "global_blockers": [
            "No exact product manifest, shipped version/branch and binary/source mapping.",
            "No official Ark Git object store verification for all parent/fixed identities.",
            "No GN target, args.gn, compile database, include closure or preprocessed TU for the product profile.",
            "No per-case realistic entry, privilege boundary, attacker-controlled trigger, reachable sensitive operation or concrete CIA impact.",
            "No authorized isolated product PoC or same-profile fixed-product revalidation.",
            "No real independent holdout with reliable human adjudicated truth.",
        ],
    }
    output["payload_sha256"] = canonical_hash(output)
    (here / "C13_candidate_product_gate_audit.json").write_text(
        json.dumps(output, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )

    lines = [
        "# C13 per-candidate product gate audit",
        "",
        f"- Source review: `{review_path}`",
        f"- Pinned blob: `{REVIEW_BLOB}` / `{review_blob_sha}`",
        f"- Reviewed dispositions: {len(reviewed)}; candidate/explicit-unknown rows: {len(reviewed_candidates)}",
        f"- Ark parent/fix product candidates: {len(ark_cases)}",
        "- Gate decision: `NOT_ADMITTED`",
        "",
        "## Ark product candidates",
        "",
        "| Case | Source | Build | Entry | Permission | Trigger | Sensitive op | CIA | PoC | Fix retest |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for row in ark_cases:
        lines.append(
            f"| {row['case_id']} | {row['source_identity_status']} | {row['product_build_and_version']} | "
            f"{row['real_entry_point']} | {row['permission_or_trust_boundary']} | {row['trigger_conditions']} | "
            f"{row['reachable_sensitive_operation']} | {row['concrete_cia_impact']} | "
            f"{row['authorized_isolated_poc']} | {row['fixed_product_revalidation']} |"
        )
    lines += [
        "",
        "## Reviewed disposition rows",
        "",
        "| # | Identity | Disposition | Source identity | Product gate |",
        "|---:|---|---|---|---|",
    ]
    for row in reviewed:
        lines.append(
            f"| {row['index']} | {row['identity']} | {row['c12_disposition']} | "
            f"{row['product_gate']['source_identity']} | {row['product_gate']['admission']} |"
        )
    lines += [
        "",
        "All missing product evidence remains explicit unknown/not-run. Source-shape candidates and fixed controls are not product vulnerability confirmation.",
        "",
    ]
    (here / "C13_candidate_product_gate_audit.md").write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({"status": "GENERATED", "reviewed": len(reviewed), "ark_cases": len(ark_cases), "payload_sha256": output["payload_sha256"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
