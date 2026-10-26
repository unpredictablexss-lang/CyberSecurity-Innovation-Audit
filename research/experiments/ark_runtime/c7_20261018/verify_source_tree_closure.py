#!/usr/bin/env python3
"""Verify pinned Ark Runtime commit/tree closure for the recorded C7 cases.

This verifies Git object-tree completeness, gitlinks, and LFS pointer presence.
It deliberately does not claim complete history ancestry, remote authenticity,
submodule materialization, build reproducibility, or detector coverage.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def git(git_dir: Path, *args: str, check: bool = True, input_bytes: bytes | None = None) -> bytes:
    proc = subprocess.run(
        ["git", f"--git-dir={git_dir}", *args],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and proc.returncode:
        raise RuntimeError(
            f"git {' '.join(args)} failed ({proc.returncode}): "
            f"{proc.stderr.decode('utf-8', 'replace').strip()}"
        )
    return proc.stdout


def parse_ls_tree(raw: bytes) -> list[dict[str, str]]:
    entries = []
    for line in raw.splitlines():
        meta, path = line.split(b"\t", 1)
        mode, kind, oid = meta.decode("ascii").split(" ")
        entries.append({"mode": mode, "kind": kind, "oid": oid, "path": path.decode("utf-8", "surrogateescape")})
    return entries


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--object-db", required=True, type=Path, help="Bare Git object database")
    ap.add_argument(
        "--input-manifest",
        type=Path,
        default=Path(__file__).parent / "run_full_snapshot_20261018" / "manifest.json",
    )
    ap.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).parent / "source_tree_closure_20261019.json",
    )
    ns = ap.parse_args()
    db = ns.object_db.resolve()
    manifest_bytes = ns.input_manifest.read_bytes()
    manifest = json.loads(manifest_bytes)
    shallow_file = db / "shallow"
    shallow = sorted(shallow_file.read_text(encoding="ascii").splitlines()) if shallow_file.exists() else []
    bare = git(db, "rev-parse", "--is-bare-repository").decode().strip() == "true"
    samples = []
    all_ok = bare

    for row in manifest["samples"]:
        commit = row["commit"]
        expected_tree = row["tree"]
        observed_tree = git(db, "rev-parse", f"{commit}^{{tree}}").decode().strip()
        raw_entries = git(db, "ls-tree", "-r", "-t", "--full-tree", commit)
        entries = parse_ls_tree(raw_entries)
        leaves = [entry for entry in entries if entry["kind"] != "tree"]
        gitlinks = [entry for entry in entries if entry["mode"] == "160000" or entry["kind"] == "commit"]
        trees = [entry for entry in entries if entry["kind"] == "tree"]

        # Confirm every tree/blob object in one batch (rather than spawning Git
        # once per object), then search tracked text blobs for LFS pointers.
        object_ids = sorted({entry["oid"] for entry in entries if entry["kind"] in {"tree", "blob"}})
        object_probe_input = ("\n".join(object_ids) + "\n").encode("ascii") if object_ids else b""
        object_probe = git(db, "cat-file", "--batch-check", input_bytes=object_probe_input) if object_ids else b""
        missing = [line.decode("ascii", "replace") for line in object_probe.splitlines() if line.endswith(b" missing")]
        blob_ids = sorted({entry["oid"] for entry in leaves if entry["kind"] == "blob"})
        lfs_proc = subprocess.run(
            ["git", f"--git-dir={db}", "grep", "-n", "-I", "-F", "--full-name", "version https://git-lfs.github.com/spec/v1", commit],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        lfs_raw = lfs_proc.stdout
        lfs_scan_error = lfs_proc.returncode not in (0, 1)
        lfs_pointers = []
        if lfs_raw:
            for line in lfs_raw.decode("utf-8", "replace").splitlines():
                # git grep output: <commit>:<path>:<line>:<match>
                parts = line.split(":", 3)
                path = parts[1] if len(parts) > 1 else "unknown"
                lfs_pointers.append({"path_or_record": path, "record": line})
        lfs_attributes = [entry["path"] for entry in leaves if entry["path"].endswith(".gitattributes")]
        gitmodules = [entry["path"] for entry in leaves if entry["path"] == ".gitmodules"]
        commit_headers = git(db, "cat-file", "-p", commit).split(b"\n\n", 1)[0].decode("ascii", "replace")
        parents = [line.split(" ", 1)[1] for line in commit_headers.splitlines() if line.startswith("parent ")]
        row_ok = (
            observed_tree == expected_tree
            and not missing
            and not gitlinks
            and not lfs_pointers
            and not lfs_scan_error
            and row.get("source_inventory_blocker") is None
        )
        all_ok = all_ok and row_ok
        samples.append(
            {
                "sample_id": row["sample_id"],
                "commit": commit,
                "commit_is_shallow_boundary": commit in shallow,
                "parents_declared_by_commit": parents,
                "tree_expected": expected_tree,
                "tree_observed": observed_tree,
                "tree_match": observed_tree == expected_tree,
                "recursive_tree_entries_including_directories": len(entries),
                "recursive_leaf_entries": len(leaves),
                "tree_objects": len(trees),
                "unique_tree_and_blob_objects_checked": len(object_ids),
                "unique_blob_objects_read": len(blob_ids),
                "read_blob_bytes_total_unique": None,
                "missing_objects": missing,
                "gitlinks": gitlinks,
                "gitmodules_paths": gitmodules,
                "gitattributes_paths": lfs_attributes,
                "lfs_pointer_blobs": lfs_pointers,
                "lfs_search_exit_code": lfs_proc.returncode,
                "lfs_search_error": lfs_proc.stderr.decode("utf-8", "replace").strip() if lfs_scan_error else None,
                "full_tree_closure_status": "complete" if row_ok else "blocked",
                "closure_scope_note": "Complete recursive commit tree closure only; does not prove full parent history or external LFS payload availability.",
            }
        )

    fsck_proc = subprocess.run(
        [
            "git",
            f"--git-dir={db}",
            "fsck",
            "--full",
            "--no-reflogs",
            "--connectivity-only",
            *[row["commit"] for row in manifest["samples"]],
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    fsck_lines = fsck_proc.stdout.decode("utf-8", "replace").splitlines()
    fsck_errors = [line for line in fsck_lines if any(token in line.lower() for token in ("missing", "error", "corrupt", "bad object"))]
    all_ok = all_ok and fsck_proc.returncode == 0 and not fsck_errors

    report = {
        "schema": "c7-source-tree-closure.v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "object_database": str(db),
        "object_database_sha1_format": git(db, "rev-parse", "--show-object-format").decode().strip(),
        "bare_object_database": bare,
        "worktree_state": "not_applicable_bare_object_database_has_no_checkout",
        "shallow_boundary_count": len(shallow),
        "shallow_commits": shallow,
        "source_manifest_path": str(ns.input_manifest.resolve()),
        "source_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "source_repo_claim": manifest["source_repository"].get("declared_repository"),
        "commit_history_completeness": "partial_shallow_boundaries_present",
        "full_tree_closure_status": "complete_for_all_selected_commits" if all_ok else "blocked",
        "git_fsck": {
            "command": "git fsck --full --no-reflogs --connectivity-only <five selected commits>",
            "exit_code": fsck_proc.returncode,
            "error_lines": fsck_errors,
            "non_error_diagnostic_lines": fsck_lines,
        },
        "source_tree_completeness_is_not_build_or_detector_coverage": True,
        "samples": samples,
        "interpretation": {
            "gitlinks": "No gitlink entries means the selected Git trees do not depend on submodule worktrees.",
            "lfs": "No pointer blobs means selected Git blobs contain no standard Git LFS pointer headers; this is not a claim about external build inputs.",
            "dirty_state": "The object database is bare, so it has no checkout dirty state. This says nothing about the separate shared repository worktree.",
            "history": "Depth-limited fetch records shallow boundaries; parent ancestry outside those boundaries is not proven complete.",
            "build": "A complete selected source tree does not establish product build/profile, preprocessing, or detector semantic completeness.",
        },
    }
    ns.output.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    ns.output.write_bytes(encoded)
    print(json.dumps({"status": report["full_tree_closure_status"], "output": str(ns.output), "sha256": hashlib.sha256(encoded).hexdigest(), "samples": len(samples)}, indent=2))
    return 0 if all_ok else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # evidence tool must fail closed with a useful diagnostic
        print(f"blocked: {exc}", file=sys.stderr)
        raise SystemExit(2)
