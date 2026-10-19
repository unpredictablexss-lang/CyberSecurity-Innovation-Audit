#!/usr/bin/env python3
"""Build or verify file-level Ark parent/fix source identity evidence.

This tool verifies raw source bytes against recorded Git blob SHA-1 and SHA-256
values. It does not verify Git commits, trees, ancestry, product applicability,
builds, or preprocessing. Network access is explicit via --fetch; offline mode
requires a local evidence directory containing the raw bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROFILE_DIR = Path(__file__).resolve().parent
PROFILE_MANIFEST = PROFILE_DIR / "ark_parent_fix_build_profile_manifest.v1.json"
EVIDENCE_PATH = PROFILE_DIR / "source_identity_evidence.v1.json"
EVIDENCE_SCHEMA = "ohscanner.ark-parent-fix-source-identity-evidence/v1"


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def expected_files(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for case in manifest.get("cases", []):
        if case.get("source_identity_status") != "recorded_complete":
            continue
        for side in ("parent", "fixed"):
            version = case[side]
            for item in version.get("files", []):
                rows.append({
                    "case_id": case["case_id"],
                    "side": side,
                    "commit": version.get("commit"),
                    "recorded_tree": version.get("tree"),
                    "path": item["path"],
                    "expected_blob_oid": item["recorded_git_blob_oid"],
                    "expected_source_sha256": item["recorded_source_sha256"],
                    "expected_bytes": item.get("recorded_bytes"),
                    "raw_url": f"https://raw.githubusercontent.com/openharmony/arkcompiler_ets_runtime/{version['commit']}/{item['path']}",
                })
    return rows


def verify_bytes(row: dict[str, Any], data: bytes) -> dict[str, Any]:
    got_blob, got_sha = blob_sha1(data), sha256(data)
    byte_match = None if row["expected_bytes"] is None else len(data) == row["expected_bytes"]
    checks = {
        "blob_oid_match": got_blob == row["expected_blob_oid"],
        "source_sha256_match": got_sha == row["expected_source_sha256"],
        "recorded_bytes_match": byte_match,
    }
    return {
        **row,
        "observed_bytes": len(data),
        "observed_blob_oid": got_blob,
        "observed_source_sha256": got_sha,
        "checks": checks,
        "recorded_bytes_status": "not_recorded" if byte_match is None else "matched" if byte_match else "mismatch",
        "status": "matched" if checks["blob_oid_match"] and checks["source_sha256_match"] and byte_match is not False else "mismatch",
    }


def fetch_bytes(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "OHScanner-C-D2-source-identity-verifier/1"})
    with urllib.request.urlopen(request, timeout=30) as response:
        if response.status != 200:
            raise OSError(f"unexpected HTTP status {response.status}")
        return response.read()


def build_evidence(manifest: dict[str, Any], fetch: bool, evidence_dir: Path | None) -> dict[str, Any]:
    results = []
    for row in expected_files(manifest):
        if fetch:
            try:
                data = fetch_bytes(row["raw_url"])
                result = verify_bytes(row, data)
                result["acquisition"] = "github_raw_http"
            except (OSError, urllib.error.URLError, TimeoutError) as exc:
                result = {**row, "status": "unavailable", "acquisition": "github_raw_http", "error": type(exc).__name__}
        elif evidence_dir is not None:
            local = evidence_dir.joinpath(row["commit"], *Path(row["path"]).parts)
            try:
                result = verify_bytes(row, local.read_bytes())
                result["acquisition"] = "local_raw_bytes"
                result["evidence_path"] = local.relative_to(evidence_dir).as_posix()
            except OSError as exc:
                result = {**row, "status": "unavailable", "acquisition": "local_raw_bytes", "error": type(exc).__name__}
        else:
            result = {**row, "status": "not_checked", "acquisition": "none"}
        results.append(result)

    matched = sum(row["status"] == "matched" for row in results)
    errors = [row for row in results if row["status"] != "matched"]
    recorded_trees = {
        (row["commit"], row["recorded_tree"])
        for row in expected_files(manifest)
        if row.get("recorded_tree")
    }
    payload: dict[str, Any] = {
        "schema": EVIDENCE_SCHEMA,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_evidence_scope": "raw source file bytes only; no commit/tree/ancestry proof",
        "acquisition_method": "github_raw_http" if fetch else "local_raw_bytes" if evidence_dir else "not_run",
        "expected_file_count": len(results),
        "matched_file_count": matched,
        "mismatched_or_unavailable_count": len(errors),
        "source_identity_status": "verified_file_bytes" if results and not errors else "incomplete_or_mismatch",
        "tree_verification": {
            "status": "NOT_VERIFIED",
            "distinct_commit_tree_pairs": len(recorded_trees),
            "reason": "Raw file content hashes do not prove the recorded Git tree, commit object, or ancestry.",
        },
        "product_profile": {
            "build_profile_status": "BLOCKED",
            "preprocess_profile_status": "BLOCKED",
            "complete_case_count": 0,
            "source_identity_is_not_product_profile": True,
        },
        "file_evidence": results,
        "blockers": [
            "official Ark Git object database is unavailable for commit/tree/ancestry and dependency closure verification",
            "product owner has not supplied exact product manifest, version/branch, and GN target",
            "product args.gn, compile database, exact compile action, compiler/linker/sysroot identity, and generated inputs are absent",
            "complete include closure and preprocessed translation-unit outputs/macro logs are absent",
            "source-to-shipped-product binary/version/branch mapping is absent",
        ],
        "metrics": {"case_count": 16, "recorded_complete_source_identity_cases": 6, "verified_file_count": matched, "tree_sha_count_unverified": 12},
    }
    payload["evidence_sha256"] = sha256(canonical_json_bytes(payload))
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=PROFILE_MANIFEST)
    parser.add_argument("--output", type=Path, default=EVIDENCE_PATH)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--fetch", action="store_true", help="Fetch immutable raw files at pinned commits and verify hashes")
    source.add_argument("--evidence-dir", type=Path, help="Verify local bytes under <dir>/<commit>/<path>")
    source.add_argument("--verify-only", action="store_true", help="Validate saved evidence structure/status; no network or source bytes")
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    if args.verify_only:
        evidence = json.loads(args.output.read_text(encoding="utf-8"))
        expected = expected_files(manifest)
        actual = evidence.get("file_evidence", [])
        ids = lambda rows: [(r.get("case_id"), r.get("side"), r.get("commit"), r.get("path")) for r in rows]
        errors = []
        if evidence.get("schema") != EVIDENCE_SCHEMA:
            errors.append("schema_mismatch")
        if ids(expected) != ids(actual):
            errors.append("file_set_mismatch")
        expected_by_id = {ids([row])[0]: row for row in expected}
        for row in actual:
            expected_row = expected_by_id.get(ids([row])[0])
            if expected_row is None:
                continue
            for key, value in expected_row.items():
                if row.get(key) != value:
                    errors.append(f"expected_identity_mismatch:{key}:{row.get('case_id')}:{row.get('path')}")
                    break
            if row.get("status") == "matched":
                checks = row.get("checks", {})
                if not all(checks.get(key) is True for key in ("blob_oid_match", "source_sha256_match")):
                    errors.append(f"matched_without_all_checks:{row.get('case_id')}:{row.get('path')}")
                if row.get("expected_bytes") is None:
                    if row.get("recorded_bytes_status") != "not_recorded" or checks.get("recorded_bytes_match") is not None:
                        errors.append(f"missing_length_not_disclosed:{row.get('case_id')}:{row.get('path')}")
                elif checks.get("recorded_bytes_match") is not True or row.get("recorded_bytes_status") != "matched":
                    errors.append(f"recorded_length_mismatch:{row.get('case_id')}:{row.get('path')}")
                if row.get("observed_blob_oid") != row.get("expected_blob_oid") or row.get("observed_source_sha256") != row.get("expected_source_sha256"):
                    errors.append(f"observed_identity_mismatch:{row.get('case_id')}:{row.get('path')}")
        if evidence.get("expected_file_count") != len(expected):
            errors.append("count_mismatch")
        if evidence.get("matched_file_count") != sum(r.get("status") == "matched" for r in actual):
            errors.append("match_count_inconsistent")
        if evidence.get("tree_verification", {}).get("status") != "NOT_VERIFIED":
            errors.append("unsafe_tree_status")
        if evidence.get("tree_verification", {}).get("distinct_commit_tree_pairs") != 12:
            errors.append("tree_pair_count_mismatch")
        if evidence.get("metrics", {}).get("tree_sha_count_unverified") != 12:
            errors.append("unverified_tree_count_mismatch")
        if evidence.get("product_profile", {}).get("build_profile_status") != "BLOCKED" or evidence.get("product_profile", {}).get("preprocess_profile_status") != "BLOCKED":
            errors.append("unsafe_product_profile_status")
        recorded_digest = evidence.get("evidence_sha256")
        unsigned = dict(evidence)
        unsigned.pop("evidence_sha256", None)
        if recorded_digest != sha256(canonical_json_bytes(unsigned)):
            errors.append("evidence_record_hash_mismatch")
        result = {"status": "verified_source_evidence_record" if not errors else "verification_failed", "expected_file_count": len(expected), "matched_file_count": evidence.get("matched_file_count"), "errors": errors}
        print(json.dumps(result, indent=2))
        return 0 if not errors else 2
    evidence = build_evidence(manifest, args.fetch, args.evidence_dir)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": evidence["source_identity_status"], "expected_file_count": evidence["expected_file_count"], "matched_file_count": evidence["matched_file_count"], "tree_verification": evidence["tree_verification"]["status"], "build_profile": evidence["product_profile"]["build_profile_status"], "preprocess_profile": evidence["product_profile"]["preprocess_profile_status"]}, indent=2))
    return 0 if evidence["expected_file_count"] == evidence["matched_file_count"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
