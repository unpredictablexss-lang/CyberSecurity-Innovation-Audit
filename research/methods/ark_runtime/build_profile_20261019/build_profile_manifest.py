#!/usr/bin/env python3
"""Recompute a fail-closed Ark parent/fix build/preprocess profile manifest.

The script reads only pinned local Git objects and local evidence. It never
fetches, checks out, builds, preprocesses, or executes target code. Missing
product build/profile inputs remain explicit blockers.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

LEDGER_COMMIT = "e4e0761501a83ac25cc67d04c527eefe9f4a1b50"
LEDGER_PATH = "research/deliveries/c-line/ark-runtime-coverage-ledger-20261019.json"
SOURCE_AUDIT_COMMIT = LEDGER_COMMIT
SOURCE_AUDIT_TREE = "307ac8237263db793028e0bf34a82a85f60821a5"
SOURCE_AUDIT_BLOB = "dbedea677c8dc70c1b0066c7bc52df27bcff06ea"
SOURCE_AUDIT_PATH = "research/deliveries/c-line/OHScanner_G盘源码漏洞审查记录_20261018.md"
SOURCE_AUDIT_SHA256 = "732b17b4adba11f1fefb93940859d951e03d35a69987b77a61f9a785eefe1240"
PROFILE_SCHEMA = "ohscanner.ark-parent-fix-build-preprocess-profile/v1"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX256 = re.compile(r"^[0-9a-f]{64}$")


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def run_git(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.STDOUT)


def git_object(repo: Path, revision: str) -> dict[str, Any]:
    object_type = run_git(repo, "cat-file", "-t", revision).decode("ascii").strip()
    size = int(run_git(repo, "cat-file", "-s", revision).decode("ascii").strip())
    return {"oid": revision, "type": object_type, "bytes": size}


def file_identity(path: Path, repo: Path | None = None) -> dict[str, Any]:
    data = path.read_bytes()
    item = {
        "path": str(path),
        "bytes": len(data),
        "sha256": sha256_bytes(data),
        "git_blob_sha1_recomputed": git_blob_sha1(data),
    }
    if repo is not None:
        try:
            rel = path.resolve().relative_to(repo.resolve()).as_posix()
            item["workspace_path"] = rel
            item["tracked_git_blob_oid"] = run_git(repo, "hash-object", rel).decode("ascii").strip()
        except (ValueError, subprocess.CalledProcessError):
            item["workspace_path"] = None
            item["tracked_git_blob_oid"] = None
    return item


def probe_tool(name: str) -> dict[str, Any]:
    executable = shutil.which(name)
    if not executable:
        return {"name": name, "status": "unavailable_on_host_path", "path": None, "sha256": None, "version": None}
    path = Path(executable)
    try:
        data = path.read_bytes()
        digest = sha256_bytes(data)
    except OSError:
        digest = None
    try:
        version = subprocess.check_output([executable, "--version"], stderr=subprocess.STDOUT, text=True).splitlines()[0]
    except (OSError, subprocess.CalledProcessError, IndexError):
        version = None
    return {"name": name, "status": "host_tool_observed_not_product_toolchain", "path": str(path), "sha256": digest, "version": version}


def python_runtime_identity() -> dict[str, Any]:
    executable = Path(sys.executable)
    data = executable.read_bytes()
    modules: dict[str, Any] = {}
    for name in ("tree_sitter", "tree_sitter_c", "tree_sitter_cpp"):
        try:
            module = __import__(name)
            module_path = Path(module.__file__)
            modules[name] = {
                "module_path": str(module_path),
                "module_sha256": sha256_bytes(module_path.read_bytes()),
                "version": getattr(module, "__version__", None),
            }
        except Exception as exc:  # explicit identity unavailable
            modules[name] = {"status": "unavailable", "error": type(exc).__name__}
    return {
        "implementation": platform.python_implementation(),
        "version": platform.python_version(),
        "executable": str(executable),
        "executable_sha256": sha256_bytes(data),
        "parser_modules": modules,
    }


def source_identity_entry(file_item: Any) -> dict[str, Any]:
    if not isinstance(file_item, dict):
        return {
            "path": file_item if isinstance(file_item, str) else None,
            "recorded_git_blob_oid": None,
            "recorded_source_sha256": None,
            "recorded_bytes": None,
            "identity_schema_valid": False,
            "local_git_object_verification": "not_verified_official_ark_store_unavailable",
            "source_bytes_available_in_this_checkout": False,
        }
    blob = file_item.get("blob")
    digest = file_item.get("sha256")
    return {
        "path": file_item.get("path"),
        "recorded_git_blob_oid": blob,
        "recorded_source_sha256": digest,
        "recorded_bytes": file_item.get("bytes"),
        "identity_schema_valid": bool(
            isinstance(file_item.get("path"), str)
            and isinstance(blob, str)
            and HEX40.fullmatch(blob)
            and isinstance(digest, str)
            and HEX256.fullmatch(digest)
        ),
        "local_git_object_verification": "not_verified_official_ark_store_unavailable",
        "source_bytes_available_in_this_checkout": False,
    }


def normalized_case(case: dict[str, Any]) -> dict[str, Any]:
    parent_files = [source_identity_entry(item) for item in case.get("vulnerable_files", [])]
    fixed_files = [source_identity_entry(item) for item in case.get("fixed_files", [])]
    complete_identity = bool(
        case.get("vulnerable_commit")
        and case.get("vulnerable_tree")
        and case.get("fixed_commit")
        and case.get("fixed_tree")
        and parent_files
        and fixed_files
        and all(item["identity_schema_valid"] for item in parent_files + fixed_files)
    )
    blockers = [
        "official Ark Git object store is not bound by OHSCANNER_ARK_OFFICIAL_GIT",
        "exact product args.gn / GN target / product manifest is absent",
        "compiler and preprocessor toolchain identity is absent",
        "compile_commands.json and exact include closure are absent",
        "preprocessed translation-unit outputs and macro expansion log are absent",
        "source-to-shipped-product binary/version/branch binding is absent",
    ]
    if not complete_identity:
        blockers.insert(0, "one or more parent/fixed commit/tree/blob/source identities are incomplete")
    return {
        "case_id": case.get("case_id"),
        "evidence_class": "development_case_not_independent_holdout",
        "component": case.get("component"),
        "cve_or_advisory": case.get("CVE_or_advisory"),
        "parent": {
            "commit": case.get("vulnerable_commit"),
            "tree": case.get("vulnerable_tree"),
            "files": parent_files,
        },
        "fixed": {
            "commit": case.get("fixed_commit"),
            "tree": case.get("fixed_tree"),
            "files": fixed_files,
        },
        "source_identity_status": "recorded_complete" if complete_identity else "recorded_incomplete",
        "build_profile": {
            "status": "BLOCKED",
            "product_manifest_locked": False,
            "product_target": None,
            "args_gn": None,
            "compile_commands_json": None,
            "include_closure": None,
            "preprocessor": {"status": "NOT_RUN", "outputs": [], "macro_expansion_log": None},
            "toolchain": {"product_compiler": None, "product_linker": None, "sysroot": None},
        },
        "preprocess_profile": {
            "declared_scan_profile": "light-ast",
            "macro_expansion": False,
            "translation_unit": None,
            "actual_include_closure": None,
            "status": "BLOCKED",
        },
        "product_association": case.get("product_build_association"),
        "scan_scope": (case.get("baseline_scan", {}).get("scope") or case.get("baseline_scan", {}).get("declared_scope")) if isinstance(case.get("baseline_scan"), dict) else None,
        "blockers": blockers,
    }


def build_manifest(repo: Path) -> dict[str, Any]:
    ledger_blob = run_git(repo, "show", f"{LEDGER_COMMIT}:{LEDGER_PATH}")
    ledger = json.loads(ledger_blob)
    audit_blob = run_git(repo, "cat-file", "blob", SOURCE_AUDIT_BLOB)
    audit_identity_ok = (
        sha256_bytes(audit_blob) == SOURCE_AUDIT_SHA256
        and git_blob_sha1(audit_blob) == SOURCE_AUDIT_BLOB
    )
    source_hashes_path = repo / "research/experiments/ark_runtime/c11_alias_cross_helper_20261019/source-hashes.json"
    syntax_path = repo / "src/ohscanner/detectors/ark_runtime/syntax.py"
    model_path = repo / "src/ohscanner/detectors/ark_runtime/model.py"
    profile_spec = Path(__file__).with_name("profile-spec.json")
    cases = [normalized_case(case) for case in ledger.get("cases", [])]
    required = [
        "commit", "tree", "blob", "source_sha256",
        "detector_rule_version", "scope", "profile", "config_hash",
        "parser_identity", "toolchain_identity",
    ]
    payload = {
        "schema": PROFILE_SCHEMA,
        "status": "BLOCKED",
        "decision": "NOT_ADMITTED",
        "generated_from": {
            "ohscanner_repository": run_git(repo, "remote", "get-url", "origin").decode("utf-8").strip(),
            "ohscanner_head": run_git(repo, "rev-parse", "HEAD").decode("ascii").strip(),
            "ohscanner_tree": run_git(repo, "rev-parse", "HEAD^{tree}").decode("ascii").strip(),
            "ledger_commit": LEDGER_COMMIT,
            "ledger_path": LEDGER_PATH,
            "ledger_blob_oid": git_blob_sha1(ledger_blob),
            "ledger_sha256": sha256_bytes(ledger_blob),
        },
        "source_audit_identity": {
            "path": SOURCE_AUDIT_PATH,
            "commit": SOURCE_AUDIT_COMMIT,
            "tree": SOURCE_AUDIT_TREE,
            "blob": SOURCE_AUDIT_BLOB,
            "sha256": SOURCE_AUDIT_SHA256,
            "local_pinned_object_verified": audit_identity_ok,
        },
        "required_identity_fields": required,
        "identity_coverage": {
            "all_required_present_for_product_build": False,
            "missing_for_product_build": [
                "product commit/tree/blob/source mapping",
                "Detector/rule version bound to exact product source",
                "scope/profile tied to product target",
                "config_hash",
                "parser binary identity",
                "product toolchain identity",
            ],
        },
        "detector_identity": {
            "detector_id": "ohscanner.ark.runtime.type_safety",
            "detector_version": "0.6.2",
            "source_hashes_manifest": file_identity(source_hashes_path, repo) if source_hashes_path.exists() else None,
        },
        "parser_identity": {
            "implementation_source": file_identity(syntax_path, repo) if syntax_path.exists() else None,
            "model_source": file_identity(model_path, repo) if model_path.exists() else None,
            "runtime": python_runtime_identity(),
            "binary_identity_complete": False,
        },
        "config_identity": {
            "profile_spec": file_identity(profile_spec) if profile_spec.exists() else None,
            "profile_id": "light-ast",
            "preprocessing_enabled": False,
        },
        "host_toolchain_probe": {
            "note": "Host probes are not the target product toolchain.",
            "python": python_runtime_identity(),
            "tools": [probe_tool(name) for name in ("git", "clang", "clang++", "cmake", "ninja", "gn")],
        },
        "cases": cases,
        "global_blockers": [
            "No product build/profile manifest is locked.",
            "No product preprocessed translation units or complete include closure are available.",
            "No shipped product binary/version/branch/source association is established.",
            "No product entry/privilege/trigger/CIA/PoC/fix revalidation closure is established.",
        ],
        "metrics": {
            "case_count": len(cases),
            "recorded_complete_source_identity_count": sum(c["source_identity_status"] == "recorded_complete" for c in cases),
            "product_build_profile_complete_count": 0,
            "precision": None,
            "recall": None,
            "reason_no_metrics": "No independent reliable labelled holdout exists.",
        },
    }
    payload["payload_sha256"] = sha256_bytes(canonical_json_bytes(payload))
    return payload


def verify_manifest(repo: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    recomputed = build_manifest(repo)
    errors = []
    if manifest.get("schema") != PROFILE_SCHEMA:
        errors.append("schema_mismatch")
    if manifest.get("payload_sha256") != recomputed.get("payload_sha256"):
        errors.append("payload_drift")
    if not manifest.get("source_audit_identity", {}).get("local_pinned_object_verified"):
        errors.append("source_audit_object_not_verified")
    if any(case.get("build_profile", {}).get("status") != "BLOCKED" for case in manifest.get("cases", [])):
        errors.append("unsafe_unblocked_build_profile_without_evidence")
    return {
        "schema": "ohscanner.ark-parent-fix-build-preprocess-verification/v1",
        "status": "verified_blocked_manifest" if not errors else "verification_failed",
        "expected_payload_sha256": manifest.get("payload_sha256"),
        "recomputed_payload_sha256": recomputed.get("payload_sha256"),
        "case_count": len(manifest.get("cases", [])),
        "errors": errors,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name("ark_parent_fix_build_profile_manifest.v1.json"))
    parser.add_argument("--verification-output", type=Path, default=Path(__file__).with_name("verification.json"))
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args(argv)
    repo = args.repo_root.resolve()
    if args.verify_only:
        manifest = json.loads(args.output.read_text(encoding="utf-8"))
    else:
        manifest = build_manifest(repo)
        args.output.write_text(json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    verification = verify_manifest(repo, manifest)
    args.verification_output.write_text(json.dumps(verification, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(verification, ensure_ascii=False, sort_keys=True, indent=2))
    return 0 if verification["status"] == "verified_blocked_manifest" else 2


if __name__ == "__main__":
    raise SystemExit(main())