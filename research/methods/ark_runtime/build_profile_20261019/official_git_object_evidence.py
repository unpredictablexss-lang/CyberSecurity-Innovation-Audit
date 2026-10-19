#!/usr/bin/env python3
"""Verify the six recorded Ark parent/fix pairs against the configured bare Git store.

This is an offline, read-only check of Git commit/tree/blob objects, recorded raw
file hashes/lengths, and parent-to-fix ancestry. The configured origin URL is
checked against the official OpenHarmony Gitee URL; this does not cryptographically
prove how the local object database was populated. Product build/preprocess status
is always kept blocked.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROFILE_DIR = Path(__file__).resolve().parent
MANIFEST_PATH = PROFILE_DIR / "ark_parent_fix_build_profile_manifest.v1.json"
OUTPUT_PATH = PROFILE_DIR / "official_git_object_evidence.v1.json"
SCHEMA = "ohscanner.ark-parent-fix-official-git-object-evidence/v1"
OFFICIAL_REMOTE = "https://gitee.com/openharmony/arkcompiler_ets_runtime.git"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_CASES = 6
EXPECTED_FILES = 26
EXPECTED_COMMIT_TREE_PAIRS = 12
EXPECTED_PROFILE_MANIFEST_SHA256 = "a33c893cce5ba4bd2dbc80e7f94b3ce47a5c6c0ed8b62f5157fb7db8aeb7c214"
EXPECTED_COMPLETE_CASE_IDS = (
    "OH-I7E0FM-TYPEDARRAY-FILTER-ABRUPT-COMPLETION",
    "ARK-ARRAY-EVERY-WRAPPED-CALLBACK-EXCEPTION-I5XZRO",
    "ARK-ARRAY-FINDINDEX-STABLE-ABRUPT-RETURN-C333",
    "ARK-COMPILER-REFLECT-APPLY-PENDING-EXCEPTION-IAO7GO",
    "ARK-TYPEDARRAY-CREATEFROMTYPEDARRAY-BYTE-LENGTH-OVERFLOW-I7KZJ7",
    "ARK-TYPEDARRAY-FILTER-RESULT-TYPE-ORIGIN-IBS5YG",
)
EXPECTED_REQUIRED_IDENTITY_FIELDS = (
    "commit", "tree", "blob", "source_sha256", "detector_rule_version", "scope",
    "profile", "config_hash", "parser_identity", "toolchain_identity",
)


class StoreError(RuntimeError):
    pass


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def run_git(git_dir: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(["git", "--git-dir", str(git_dir), *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and result.returncode:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise StoreError(f"git {' '.join(args)} failed ({result.returncode}): {message}")
    return result


def normalized_remote(url: str) -> str:
    return url.strip().rstrip("/").lower()


def resolve_store(cli_path: Path | None, environ: dict[str, str] | None = None) -> tuple[Path, dict[str, Any]]:
    env = os.environ if environ is None else environ
    configured = str(cli_path) if cli_path is not None else env.get("OHSCANNER_ARK_OFFICIAL_GIT", "")
    if not configured.strip():
        raise StoreError("official Git store not configured; pass --git-dir or set OHSCANNER_ARK_OFFICIAL_GIT")
    git_dir = Path(configured).expanduser().resolve()
    if not git_dir.exists() or not git_dir.is_dir():
        raise StoreError("configured Git store path does not exist or is not a directory")
    bare = run_git(git_dir, "rev-parse", "--is-bare-repository").stdout.decode("ascii", errors="replace").strip() == "true"
    if not bare:
        raise StoreError("configured Git store is not a bare repository")
    fetch_urls = [x for x in run_git(git_dir, "remote", "get-url", "--all", "origin").stdout.decode("utf-8", errors="replace").splitlines() if x.strip()]
    push_urls = [x for x in run_git(git_dir, "remote", "get-url", "--push", "--all", "origin").stdout.decode("utf-8", errors="replace").splitlines() if x.strip()]
    official = normalized_remote(OFFICIAL_REMOTE)
    if len(fetch_urls) != 1 or normalized_remote(fetch_urls[0]) != official:
        raise StoreError("origin fetch URL must be exactly the official OpenHarmony Gitee repository")
    if len(push_urls) != 1 or normalized_remote(push_urls[0]) != official:
        raise StoreError("origin push URL must be exactly the official OpenHarmony Gitee repository")
    shallow_text = run_git(git_dir, "rev-parse", "--is-shallow-repository").stdout.decode("ascii", errors="replace").strip()
    if shallow_text != "false":
        raise StoreError("configured Git store must be non-shallow to evaluate ancestry")
    return git_dir, {
        "git_dir": str(git_dir),
        "bare": True,
        "shallow": False,
        "origin_fetch_urls": fetch_urls,
        "origin_push_urls": push_urls,
        "expected_official_remote": OFFICIAL_REMOTE,
        "remote_validation": "matched",
        "network_used": False,
    }


def recorded_cases(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    return [case for case in manifest.get("cases", []) if case.get("source_identity_status") == "recorded_complete"]


def validate_manifest_identity(manifest: dict[str, Any]) -> dict[str, Any]:
    recorded_digest = manifest.get("payload_sha256")
    unsigned = dict(manifest)
    unsigned.pop("payload_sha256", None)
    computed_digest = sha256(canonical_json_bytes(unsigned))
    complete_ids = tuple(case.get("case_id") for case in recorded_cases(manifest))
    errors = []
    if manifest.get("schema") != "ohscanner.ark-parent-fix-build-preprocess-profile/v1":
        errors.append("manifest_schema_mismatch")
    if list(manifest.get("required_identity_fields", [])) != list(EXPECTED_REQUIRED_IDENTITY_FIELDS):
        errors.append("required_identity_fields_mismatch")
    if recorded_digest != computed_digest:
        errors.append("manifest_internal_digest_mismatch")
    if recorded_digest != EXPECTED_PROFILE_MANIFEST_SHA256:
        errors.append("manifest_not_pinned")
    if complete_ids != EXPECTED_COMPLETE_CASE_IDS:
        errors.append("complete_case_id_mismatch")
    if len(manifest.get("cases", [])) != 16:
        errors.append("manifest_case_count_mismatch")
    if manifest.get("status") != "BLOCKED" or manifest.get("decision") != "NOT_ADMITTED":
        errors.append("manifest_product_gate_not_blocked")
    if manifest.get("metrics", {}).get("product_build_profile_complete_count") != 0:
        errors.append("manifest_product_profile_count_not_zero")
    if any(case.get("build_profile", {}).get("status") != "BLOCKED" or case.get("preprocess_profile", {}).get("status") != "BLOCKED" for case in manifest.get("cases", [])):
        errors.append("manifest_contains_unblocked_product_profile")
    return {
        "status": "pinned_manifest" if not errors else "manifest_identity_unpinned",
        "expected_payload_sha256": EXPECTED_PROFILE_MANIFEST_SHA256,
        "recorded_payload_sha256": recorded_digest,
        "computed_payload_sha256": computed_digest,
        "expected_complete_case_ids": list(EXPECTED_COMPLETE_CASE_IDS),
        "observed_complete_case_ids": list(complete_ids),
        "errors": errors,
        "scope_note": "The pinned hash locks this evidence input to the reviewed manifest snapshot; it is not a signature or provenance attestation.",
    }


def verify_one_side(git_dir: Path, case_id: str, side: str, item: dict[str, Any]) -> dict[str, Any]:
    commit = item.get("commit")
    tree_expected = item.get("tree")
    errors: list[str] = []
    commit_type = None
    commit_tree = None
    try:
        commit_type = run_git(git_dir, "cat-file", "-t", str(commit)).stdout.decode("ascii").strip()
        if commit_type != "commit":
            errors.append("commit_object_type_mismatch")
    except StoreError:
        errors.append("commit_object_missing_or_unreadable")
    try:
        tree_type = run_git(git_dir, "cat-file", "-t", str(tree_expected)).stdout.decode("ascii").strip()
        if tree_type != "tree":
            errors.append("tree_object_type_mismatch")
        commit_tree = run_git(git_dir, "rev-parse", f"{commit}^{{tree}}").stdout.decode("ascii").strip()
        if commit_tree != tree_expected:
            errors.append("commit_tree_oid_mismatch")
    except StoreError:
        errors.append("tree_object_missing_or_commit_tree_unreadable")

    files = []
    for file_item in item.get("files", []):
        path = file_item.get("path")
        expected_blob = file_item.get("recorded_git_blob_oid")
        expected_sha256 = file_item.get("recorded_source_sha256")
        expected_bytes = file_item.get("recorded_bytes")
        file_errors: list[str] = []
        observed_blob = None
        observed_sha = None
        observed_bytes = None
        try:
            observed_blob = run_git(git_dir, "rev-parse", "--verify", f"{commit}:{path}").stdout.decode("ascii").strip()
            kind = run_git(git_dir, "cat-file", "-t", observed_blob).stdout.decode("ascii").strip()
            if kind != "blob":
                file_errors.append("path_object_not_blob")
            if observed_blob != expected_blob:
                file_errors.append("path_blob_oid_mismatch")
            data = run_git(git_dir, "cat-file", "blob", observed_blob).stdout
            observed_sha = sha256(data)
            observed_bytes = len(data)
            if git_blob_sha1(data) != observed_blob:
                file_errors.append("blob_oid_recomputation_mismatch")
            if observed_sha != expected_sha256:
                file_errors.append("source_sha256_mismatch")
            if expected_bytes is not None and observed_bytes != expected_bytes:
                file_errors.append("recorded_byte_length_mismatch")
        except StoreError:
            file_errors.append("path_or_blob_missing_or_unreadable")
        files.append({
            "path": path,
            "expected_blob_oid": expected_blob,
            "observed_blob_oid": observed_blob,
            "expected_source_sha256": expected_sha256,
            "observed_source_sha256": observed_sha,
            "expected_bytes": expected_bytes,
            "observed_bytes": observed_bytes,
            "byte_length_status": "not_recorded" if expected_bytes is None else "matched" if observed_bytes == expected_bytes else "mismatch",
            "status": "matched" if not file_errors else "mismatch",
            "errors": file_errors,
        })
        errors.extend(f"file:{path}:{error}" for error in file_errors)
    return {
        "commit": commit,
        "commit_object_type": commit_type,
        "recorded_tree": tree_expected,
        "observed_commit_tree": commit_tree,
        "tree_status": "matched" if commit_tree == tree_expected and not any(e.startswith("tree_object") or e.startswith("commit_tree") for e in errors) else "mismatch",
        "files": files,
        "status": "matched" if not errors else "mismatch",
        "errors": errors,
    }


def verify_ancestry(git_dir: Path, parent: str, fixed: str) -> dict[str, Any]:
    result = run_git(git_dir, "merge-base", "--is-ancestor", parent, fixed, check=False)
    return {
        "parent_commit": parent,
        "fixed_commit": fixed,
        "status": "matched" if result.returncode == 0 else "mismatch" if result.returncode == 1 else "unavailable",
        "is_ancestor": result.returncode == 0,
        "error": None if result.returncode in (0, 1) else result.stderr.decode("utf-8", errors="replace").strip(),
    }


def build_record(manifest: dict[str, Any], git_dir: Path, store_meta: dict[str, Any], generated_at: str | None = None, require_pinned_manifest: bool = True) -> dict[str, Any]:
    cases = recorded_cases(manifest)
    manifest_identity = validate_manifest_identity(manifest) if require_pinned_manifest else {
        "status": "synthetic_test_fixture",
        "scope_note": "Self-test fixture only; this result is not an official manifest validation.",
        "errors": [],
    }
    all_cases = []
    object_errors: list[str] = []
    tree_pairs: set[tuple[str, str]] = set()
    total_files = 0
    for case in cases:
        parent = verify_one_side(git_dir, case.get("case_id", "unknown"), "parent", case.get("parent", {}))
        fixed = verify_one_side(git_dir, case.get("case_id", "unknown"), "fixed", case.get("fixed", {}))
        ancestry = verify_ancestry(git_dir, parent["commit"], fixed["commit"])
        total_files += len(parent["files"]) + len(fixed["files"])
        for side_result in (parent, fixed):
            if side_result.get("recorded_tree"):
                tree_pairs.add((side_result["commit"], side_result["recorded_tree"]))
        case_errors = []
        if parent["status"] != "matched":
            case_errors.append("parent_object_or_source_mismatch")
        if fixed["status"] != "matched":
            case_errors.append("fixed_object_or_source_mismatch")
        if ancestry["status"] != "matched":
            case_errors.append("parent_not_ancestor_of_fixed_or_unavailable")
        object_errors.extend(f"{case.get('case_id')}:{e}" for e in case_errors)
        all_cases.append({
            "case_id": case.get("case_id"),
            "parent": parent,
            "fixed": fixed,
            "ancestry": ancestry,
            "status": "matched" if not case_errors else "mismatch",
            "errors": case_errors,
        })

    if len(cases) != EXPECTED_CASES:
        object_errors.append(f"scope_expected_{EXPECTED_CASES}_complete_cases_got_{len(cases)}")
    if total_files != EXPECTED_FILES:
        object_errors.append(f"scope_expected_{EXPECTED_FILES}_files_got_{total_files}")
    if len(tree_pairs) != EXPECTED_COMMIT_TREE_PAIRS:
        object_errors.append(f"scope_expected_{EXPECTED_COMMIT_TREE_PAIRS}_commit_tree_pairs_got_{len(tree_pairs)}")
    if manifest_identity["status"] not in ("pinned_manifest", "synthetic_test_fixture"):
        object_errors.extend(f"manifest_identity:{error}" for error in manifest_identity["errors"])

    all_case_ids = {case.get("case_id") for case in cases}
    out_of_scope = [case.get("case_id") for case in manifest.get("cases", []) if case.get("case_id") not in all_case_ids]
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "generated_at_utc": generated_at or datetime.now(timezone.utc).isoformat(),
        "status": ("verified_synthetic_fixture" if manifest_identity["status"] == "synthetic_test_fixture" else "verified_against_configured_store") if not object_errors else "verification_failed",
        "manifest_identity": manifest_identity,
        "evidence_scope": {
            "case_ids": [case.get("case_id") for case in cases],
            "complete_case_count": len(cases),
            "out_of_scope_case_count": len(out_of_scope),
            "out_of_scope_cases": out_of_scope,
            "commit_tree_pair_count": len(tree_pairs),
            "file_count": total_files,
        },
        "store": store_meta,
        "acquisition_and_custody": {
            "status": "NOT_INDEPENDENTLY_VERIFIED",
            "note": "Remote configuration and content-addressed object checks do not independently attest acquisition, custody, or server authenticity; no external signature/API attestation was supplied.",
        },
        "object_checks": {
            "commit_objects_checked": sum(2 for _ in all_cases),
            "tree_objects_checked": sum(2 for _ in all_cases),
            "path_blob_records_checked": total_files,
            "parent_ancestor_fixed_pairs_checked": len(all_cases),
            "file_sha256_and_blob_oid_recomputed": True,
            "recorded_byte_lengths": "checked_when_present; missing recorded lengths remain not_recorded",
        },
        "cases": all_cases,
        "errors": object_errors,
        "product_profile": {
            "build_profile_status": "BLOCKED",
            "preprocess_profile_status": "BLOCKED",
            "complete_case_count": 0,
            "note": "Git source object verification does not establish a product build or preprocess profile.",
        },
        "limitations": [
            "Configured origin URL and object hashes/ancestry only establish consistency with the local store's declared remote; acquisition, custody, and server authenticity are not independently verified.",
            "Only six source_identity_status=recorded_complete development cases are in scope; the other ten cases remain unverified.",
            "Twelve commit/tree identities and their source objects are checked here; dependent repository closure beyond the listed commits/files is not evaluated.",
            "No product manifest, product build, preprocess output, shipped binary mapping, exploitability, or holdout truth is verified.",
        ],
    }
    payload["evidence_sha256"] = sha256(canonical_json_bytes(payload))
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--git-dir", type=Path, help="Configured official bare Git store; otherwise read OHSCANNER_ARK_OFFICIAL_GIT")
    parser.add_argument("--output", type=Path, default=OUTPUT_PATH)
    args = parser.parse_args(argv)
    try:
        git_dir, store_meta = resolve_store(args.git_dir)
    except StoreError as exc:
        print(json.dumps({"status": "verification_failed", "error": str(exc), "evidence_written": False}, indent=2))
        return 2
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    evidence = build_record(manifest, git_dir, store_meta)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": evidence["status"],
        "complete_case_count": evidence["evidence_scope"]["complete_case_count"],
        "file_count": evidence["evidence_scope"]["file_count"],
        "commit_tree_pair_count": evidence["evidence_scope"]["commit_tree_pair_count"],
        "errors": evidence["errors"],
        "build_profile_status": evidence["product_profile"]["build_profile_status"],
        "preprocess_profile_status": evidence["product_profile"]["preprocess_profile_status"],
        "output": str(args.output),
    }, indent=2))
    return 0 if evidence["status"] == "verified_against_configured_store" else 2


if __name__ == "__main__":
    raise SystemExit(main())
