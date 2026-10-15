#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_git(cwd: Path, *args: str) -> tuple[int, str, str]:
    proc = subprocess.run(
        ["git", "-C", str(cwd), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return (
        proc.returncode,
        proc.stdout.decode("utf-8", "replace").strip(),
        proc.stderr.decode("utf-8", "replace").strip(),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--declared-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    root = args.source_root.resolve()
    tree = ET.parse(args.declared_manifest)
    projects = []
    checked_out = 0
    invalid = 0
    missing = 0
    dirty = 0
    for item in tree.findall(".//project"):
        path = item.attrib.get("path") or item.attrib.get("name", "")
        project_root = root / path
        record = {
            "name": item.attrib.get("name"),
            "path": path,
            "declared_revision": item.attrib.get("revision", "master"),
            "remote": item.attrib.get("remote", "gitcode"),
            "groups": item.attrib.get("groups", ""),
        }
        if not project_root.exists():
            record["status"] = "missing_worktree"
            missing += 1
        else:
            rc, commit, error = run_git(project_root, "rev-parse", "HEAD")
            if rc == 0 and len(commit) == 40:
                rc_tree, tree_sha, tree_error = run_git(project_root, "rev-parse", "HEAD^{tree}")
                rc_status, status_text, status_error = run_git(project_root, "status", "--porcelain")
                record.update(
                    {
                        "status": "checked_out",
                        "commit": commit,
                        "tree": tree_sha if rc_tree == 0 else None,
                        "dirty": bool(rc_status == 0 and status_text),
                    }
                )
                checked_out += 1
                dirty += int(record["dirty"])
            else:
                record.update(
                    {
                        "status": "invalid_worktree",
                        "error": error or tree_error or status_error or "git rev-parse failed",
                    }
                )
                invalid += 1
        projects.append(record)

    result = {
        "schema_version": 1,
        "kind": "partial_openharmony_pinned_source_manifest",
        "status": "partial",
        "source_root": str(root),
        "declared_manifest": {
            "path": str(args.declared_manifest),
            "sha256": sha256_file(args.declared_manifest),
            "size": args.declared_manifest.stat().st_size,
        },
        "manifest_repo_commit": run_git(root / ".repo" / "manifests", "rev-parse", "HEAD")[1],
        "counts": {
            "declared_projects": len(projects),
            "checked_out": checked_out,
            "invalid_worktrees": invalid,
            "missing_worktrees": missing,
            "dirty_checked_out": dirty,
        },
        "projects": projects,
        "limitation": "Only checked-out project worktrees are pinned by observed commit/tree; declared master revisions for missing worktrees are not pinned commits.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())