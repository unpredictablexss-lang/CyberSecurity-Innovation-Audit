#!/usr/bin/env python3
"""Verify frozen Ark Runtime profile objects through a local WSL Git object store.

This command is read-only. It never fetches, checks out, or edits source trees.
Run from the CyberSecurity-Innovation-Audit repository root on Windows.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from research.full_scan_20261018.lanes.c.model import RuntimeTypeModel  # noqa: E402

DEFAULT_GIT_DIR = "/mnt/d/openHarmonyScanner/openharmony/.repo/projects/arkcompiler/ets_runtime.git"
DEFAULT_OUTPUT = ROOT / "research/deliveries/cpp/C_LINE_SOURCE_BINDING_VERIFICATION_20261018.json"


def git(git_dir: str, *args: str) -> bytes:
    command = ["wsl.exe", "env", "GIT_NO_LAZY_FETCH=1", "git", "-C", git_dir, *args]
    completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if completed.returncode:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"Git command failed ({completed.returncode}): {args!r}: {detail}")
    return completed.stdout


def build_manifest(git_dir: str) -> dict:
    model = RuntimeTypeModel()
    profiles = []
    for commit, expected_tree, target_blob, creator_blob in model.source_profiles:
        tree = git(git_dir, "show", "-s", "--format=%T", commit).decode().strip()
        bindings = []
        for binding_commit, path, expected_oid in model.bindings_for_commit(commit):
            if binding_commit != commit:
                raise RuntimeError(f"Unexpected cross-commit model dependency: {binding_commit} {path}")
            raw = git(git_dir, "show", f"{commit}:{path}")
            actual_oid = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
            resolved_oid = git(git_dir, "rev-parse", f"{commit}:{path}").decode().strip()
            bindings.append({
                "path": path,
                "expected_blob": expected_oid,
                "resolved_blob": resolved_oid,
                "recomputed_blob": actual_oid,
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "matches": resolved_oid == expected_oid == actual_oid,
            })
        target = next(row for row in bindings if row["path"] == "ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp")
        creator = next(row for row in bindings if row["path"] == "ecmascript/compiler/new_object_stub_builder.cpp")
        profiles.append({
            "commit": commit,
            "expected_tree": expected_tree,
            "resolved_tree": tree,
            "tree_matches": tree == expected_tree,
            "expected_target_blob": target_blob,
            "target_matches": target["matches"] and target["resolved_blob"] == target_blob,
            "expected_creator_blob": creator_blob,
            "creator_matches": creator["matches"] and creator["resolved_blob"] == creator_blob,
            "model_binding_count": len(bindings),
            "all_bindings_match": all(row["matches"] for row in bindings),
            "bindings": bindings,
        })
    return {
        "schema": "ark-runtime-source-binding-verification-v1",
        "repository": "openharmony/arkcompiler_ets_runtime",
        "source_object_store": git_dir,
        "git_lazy_fetch_disabled": True,
        "method": "WSL git rev-parse/show; recompute Git blob SHA-1 and content SHA-256",
        "profiles": profiles,
        "all_profiles_match": all(
            profile["tree_matches"] and profile["target_matches"]
            and profile["creator_matches"] and profile["all_bindings_match"]
            for profile in profiles
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--git-dir", default=DEFAULT_GIT_DIR, help="WSL path to the local bare Git object store")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="JSON verification manifest output")
    args = parser.parse_args()
    try:
        manifest = build_manifest(args.git_dir)
    except (RuntimeError, OSError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    args.output.write_bytes(payload)
    print(f"all_profiles_match={str(manifest['all_profiles_match']).lower()}")
    print(f"manifest={args.output}")
    print(f"sha256={hashlib.sha256(payload).hexdigest()}")
    return 0 if manifest["all_profiles_match"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
