#!/usr/bin/env python3
"""Verify an external Ark parent/fix source and product build/preprocess bundle.

This verifier is read-only. It checks local Git objects and hashed evidence
files. It never fetches, checks out, builds, preprocesses, or runs target code.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA = "ohscanner.ark-parent-fix-product-profile-bundle/v1"
RESULT_SCHEMA = "ohscanner.ark-parent-fix-product-profile-verification/v1"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX256 = re.compile(r"^[0-9a-f]{64}$")
PRODUCT_FIELDS = (
    "product_manifest",
    "args_gn",
    "compile_commands_json",
    "include_closure",
    "toolchain_identity",
    "sysroot_identity",
    "macro_expansion_log",
)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def payload_hash(value: Any) -> str:
    return sha256(canonical_bytes(value))


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def safe_relative(value: str) -> bool:
    path = PurePosixPath(value)
    return bool(value) and not path.is_absolute() and ".." not in path.parts and "\\" not in value


def run_git(git_dir: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "--git-dir", str(git_dir), *args], stderr=subprocess.STDOUT)


def artifact_identity(path: Path, root: Path, declared: dict[str, Any], label: str, errors: list[str]) -> dict[str, Any]:
    rel = declared.get("path", "")
    if not safe_relative(rel):
        errors.append(f"unsafe_artifact_path:{label}")
        return {"label": label, "status": "invalid"}
    full = root.joinpath(*PurePosixPath(rel).parts)
    try:
        data = full.read_bytes()
    except OSError:
        errors.append(f"missing_artifact:{label}")
        return {"label": label, "status": "missing"}
    digest = sha256(data)
    if declared.get("sha256") != digest:
        errors.append(f"artifact_sha256_mismatch:{label}")
    if declared.get("bytes") != len(data):
        errors.append(f"artifact_bytes_mismatch:{label}")
    return {"label": label, "path": rel, "bytes": len(data), "sha256": digest, "status": "verified_file_identity"}


def verify_source_side(git_dir: Path, side_name: str, expected: dict[str, Any], actual: dict[str, Any], errors: list[str]) -> dict[str, Any]:
    commit = expected.get("commit")
    tree = expected.get("tree")
    if actual.get("commit") != commit or actual.get("tree") != tree:
        errors.append(f"{side_name}_commit_tree_mismatch")
    observed_files = []
    for index, expected_file in enumerate(expected.get("files", [])):
        label = f"{side_name}_file_{index}"
        path = expected_file.get("path")
        if not isinstance(path, str) or not safe_relative(path):
            errors.append(f"unsafe_source_path:{label}")
            continue
        actual_file = actual.get("files", [])[index] if index < len(actual.get("files", [])) else {}
        if actual_file != expected_file:
            errors.append(f"{side_name}_file_identity_mismatch:{label}")
        try:
            blob = run_git(git_dir, "rev-parse", f"{commit}:{path}").decode("ascii").strip()
            data = run_git(git_dir, "cat-file", "blob", blob)
        except (subprocess.CalledProcessError, OSError):
            errors.append(f"source_object_missing:{label}")
            continue
        digest = sha256(data)
        if blob != expected_file.get("blob"):
            errors.append(f"source_blob_mismatch:{label}")
        if git_blob_sha1(data) != blob:
            errors.append(f"source_blob_hash_mismatch:{label}")
        if digest != expected_file.get("sha256"):
            errors.append(f"source_sha256_mismatch:{label}")
        if expected_file.get("bytes") is not None and len(data) != expected_file.get("bytes"):
            errors.append(f"source_bytes_mismatch:{label}")
        observed_files.append({"path": path, "blob": blob, "sha256": digest, "bytes": len(data)})
    try:
        observed_tree = run_git(git_dir, "rev-parse", f"{commit}^{{tree}}").decode("ascii").strip()
        if observed_tree != tree:
            errors.append(f"{side_name}_tree_object_mismatch")
    except (subprocess.CalledProcessError, OSError):
        errors.append(f"{side_name}_tree_object_missing")
    return {"commit": commit, "tree": tree, "files": observed_files}


def verify_bundle(base: dict[str, Any], bundle: dict[str, Any], evidence_root: Path, repo_root: Path) -> dict[str, Any]:
    errors: list[str] = []
    if bundle.get("schema") != SCHEMA:
        errors.append("bundle_schema_mismatch")
    if bundle.get("status") == "TEMPLATE_NOT_EVIDENCE":
        errors.append("template_is_not_evidence")
    git_value = bundle.get("official_git_dir")
    if not isinstance(git_value, str) or not git_value:
        errors.append("official_git_dir_missing")
        git_dir = None
    else:
        git_dir = Path(git_value)
        if not git_dir.is_absolute():
            git_dir = (repo_root / git_dir).resolve()
        if not git_dir.exists():
            errors.append("official_git_dir_not_found")
        else:
            try:
                kind = run_git(git_dir, "rev-parse", "--is-bare-repository").decode("ascii").strip()
                if kind not in {"true", "false"}:
                    errors.append("official_git_dir_not_git")
            except (subprocess.CalledProcessError, OSError):
                errors.append("official_git_dir_not_git")

    product_profile = bundle.get("product_profile", {})
    product_results = []
    for field in PRODUCT_FIELDS:
        value = product_profile.get(field)
        if not isinstance(value, dict):
            errors.append(f"missing_product_profile:{field}")
            continue
        product_results.append(artifact_identity(evidence_root, evidence_root, value, field, errors))
    if isinstance(product_profile.get("gn_target"), str) and product_profile.get("gn_target"):
        gn_target = product_profile["gn_target"]
    else:
        gn_target = None
        errors.append("missing_product_profile:gn_target")

    base_cases = {item["case_id"]: item for item in base.get("cases", [])}
    bundle_cases = bundle.get("cases", {})
    if set(base_cases) != set(bundle_cases):
        errors.append("case_set_mismatch")
    case_results = []
    for case_id in sorted(base_cases):
        base_case = base_cases[case_id]
        bundle_case = bundle_cases.get(case_id, {})
        result = {
            "case_id": case_id,
            "source_identity_status": "blocked",
            "build_preprocess_status": "blocked",
        }
        if git_dir is not None and git_dir.exists():
            parent = verify_source_side(git_dir, "parent", base_case.get("parent", {}), bundle_case.get("parent", {}), errors)
            fixed = verify_source_side(git_dir, "fixed", base_case.get("fixed", {}), bundle_case.get("fixed", {}), errors)
            result["parent_observed"] = parent
            result["fixed_observed"] = fixed
            if parent["files"] and fixed["files"] and not any(error.startswith(("parent_", "fixed_")) for error in errors):
                result["source_identity_status"] = "verified"
        preprocessed = bundle_case.get("preprocessed_units", [])
        observed_preprocessed = []
        if not isinstance(preprocessed, list) or not preprocessed:
            errors.append(f"missing_preprocessed_units:{case_id}")
        else:
            for index, item in enumerate(preprocessed):
                if item.get("role") not in {"parent", "fixed"}:
                    errors.append(f"bad_preprocessed_role:{case_id}:{index}")
                observed_preprocessed.append(artifact_identity(evidence_root, evidence_root, item, f"{case_id}:preprocessed:{index}", errors))
        result["preprocessed_units"] = observed_preprocessed
        if result["source_identity_status"] == "verified" and len(observed_preprocessed) >= 2:
            result["build_preprocess_status"] = "verified"
        case_results.append(result)

    compile_commands_entry = product_profile.get("compile_commands_json") or {}
    include_closure_entry = product_profile.get("include_closure") or {}
    compile_commands_path = compile_commands_entry.get("path")
    include_closure_path = include_closure_entry.get("path")
    if compile_commands_path and safe_relative(compile_commands_path):
        try:
            compile_commands = json.loads(evidence_root.joinpath(*PurePosixPath(compile_commands_path).parts).read_text(encoding="utf-8"))
            if not isinstance(compile_commands, list) or not compile_commands:
                errors.append("compile_commands_empty")
        except (OSError, json.JSONDecodeError):
            errors.append("compile_commands_unreadable")
    if include_closure_path and safe_relative(include_closure_path):
        try:
            include_closure = json.loads(evidence_root.joinpath(*PurePosixPath(include_closure_path).parts).read_text(encoding="utf-8"))
            if not include_closure:
                errors.append("include_closure_empty")
        except (OSError, json.JSONDecodeError):
            errors.append("include_closure_unreadable")

    status = "VERIFIED_COMPLETE" if not errors else "BLOCKED"
    result = {
        "schema": RESULT_SCHEMA,
        "status": status,
        "decision": "PROFILE_COMPLETE" if status == "VERIFIED_COMPLETE" else "NOT_ADMITTED",
        "official_git_dir": str(git_dir) if git_dir else None,
        "gn_target": gn_target,
        "product_artifacts": product_results,
        "cases": case_results,
        "errors": errors,
    }
    result["payload_sha256"] = payload_hash(result)
    return result


def emit_template(base: dict[str, Any], output: Path) -> None:
    template = {
        "schema": SCHEMA,
        "status": "TEMPLATE_NOT_EVIDENCE",
        "official_git_dir": None,
        "product_profile": {field: None for field in PRODUCT_FIELDS} | {"gn_target": None},
        "cases": {
            item["case_id"]: {
                "parent": item.get("parent"),
                "fixed": item.get("fixed"),
                "preprocessed_units": [],
            }
            for item in base.get("cases", [])
        },
    }
    output.write_text(json.dumps(template, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-manifest", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--emit-template", action="store_true")
    args = parser.parse_args()
    base = json.loads(args.base_manifest.read_text(encoding="utf-8"))
    if args.emit_template:
        emit_template(base, args.bundle)
        print(json.dumps({"status": "TEMPLATE_WRITTEN", "path": str(args.bundle)}, indent=2))
        return 0
    bundle = json.loads(args.bundle.read_text(encoding="utf-8"))
    evidence_root = (args.evidence_root or args.bundle.parent).resolve()
    result = verify_bundle(base, bundle, evidence_root, args.repo_root.resolve())
    args.output.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "errors": len(result["errors"]), "payload_sha256": result["payload_sha256"]}, indent=2))
    return 0 if result["status"] == "VERIFIED_COMPLETE" else 2


if __name__ == "__main__":
    raise SystemExit(main())