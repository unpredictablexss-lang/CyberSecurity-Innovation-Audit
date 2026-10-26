#!/usr/bin/env python3
"""Check pinned package manifests for npm roots exposed by Ninja's input query."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
BASE = Path("/home/deepsleep/c-line-c1-profile-20261018")
SOURCE = BASE / "openharmony-git-archive-20261019"
PROJECT_REPOS = Path("/mnt/d/OpenHarmony807/repos")
MATERIALIZATION = HERE / "materialization_manifest_20261019.json"
INPUTS = HERE / "ninja_input_inventory_20261019.v1.json"
RESULT = HERE / "declared_npm_projects_20261019.v1.json"


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def audit_lock(path: Path) -> dict:
    lock = json.loads(path.read_text(encoding="utf-8"))
    counts = {"packages": 0, "missing_integrity": 0, "non_mirror_url": 0, "git_or_file_url": 0}

    def visit(dependencies: dict) -> None:
        for item in dependencies.values():
            counts["packages"] += 1
            resolved = item.get("resolved", "")
            counts["missing_integrity"] += not bool(item.get("integrity"))
            counts["non_mirror_url"] += not resolved.startswith("https://repo.huaweicloud.com/repository/npm/")
            counts["git_or_file_url"] += resolved.startswith(("git+", "git://", "file:"))
            visit(item.get("dependencies", {}))

    visit(lock.get("dependencies", {}))
    return {"lockfile_version": lock.get("lockfileVersion"), **counts}


def main() -> int:
    material = json.loads(MATERIALIZATION.read_text(encoding="utf-8"))
    pins = {x["path"]: x for x in material["projects"]}
    input_report = json.loads(INPUTS.read_text(encoding="utf-8"))
    roots = [x["build_path_root"] for x in input_report["node_modules_reference_roots"]]
    rows = []
    for root in roots:
        if root.startswith("NOTICE_FILES/"):
            rows.append({"source_path": root, "role": "notice-file-input", "status": "not_an_npm_install_root"})
            continue
        parts = root.split("/")
        source_rel = "/".join(parts[2:]) if root.startswith("../../") else root
        source = SOURCE / source_rel
        pin_candidates = [p for p in pins if source_rel == p or source_rel.startswith(p + "/")]
        pin = pins[max(pin_candidates, key=len)] if pin_candidates else None
        row = {
            "source_path": source_rel,
            "status": "manifest_project_found" if pin else "no_manifest_pin_found",
            "source_exists": source.is_dir(),
            "package_json_exists": (source / "package.json").is_file(),
            "package_lock_exists": (source / "package-lock.json").is_file(),
            "shrinkwrap_exists": (source / "npm-shrinkwrap.json").is_file(),
            "manifest_project": pin["path"] if pin else None,
            "manifest_commit": pin["commit"] if pin else None,
            "manifest_tree": pin["tree"] if pin else None,
        }
        repo_name = pin["name"] if pin else ""
        repo = PROJECT_REPOS / repo_name
        row["repo_tool_repo_path"] = str(repo)
        row["repo_tool_repo_exists"] = repo.is_dir()
        if repo.is_dir():
            row["repo_tool_head"] = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
            if pin:
                row["repo_tool_tree_at_pin"] = subprocess.check_output(["git", "-C", str(repo), "rev-parse", f"{pin['commit']}^{{tree}}"], text=True).strip()
        for filename in ("package.json", "package-lock.json", "npm-shrinkwrap.json"):
            path = source / filename
            if path.is_file():
                path_key = filename.replace(".", "_")
                digest = sha(path)
                row[path_key + "_sha256"] = digest
                if pin and repo.is_dir():
                    suffix = source_rel[len(pin["path"]) :].strip("/")
                    git_path = "/".join(part for part in (suffix, filename) if part)
                    oid = subprocess.check_output(
                        ["git", "-C", str(repo), "rev-parse", f"{pin['commit']}:{git_path}"], text=True
                    ).strip()
                    blob = subprocess.check_output(["git", "-C", str(repo), "cat-file", "blob", oid])
                    row[path_key + "_git_blob"] = oid
                    row[path_key + "_blob_sha256_matches"] = hashlib.sha256(blob).hexdigest() == digest
                if filename == "package-lock.json":
                    row["package_lock_audit"] = audit_lock(path)
        rows.append(row)
    result = {
        "schema": "ohscanner.c1.declared-npm-projects/v1",
        "status": "audited",
        "materialization_manifest_sha256": sha(MATERIALIZATION),
        "ninja_input_inventory_sha256": sha(INPUTS),
        "projects": rows,
        "scope_note": "These are npm-related paths declared by Ninja -t inputs all. A package manifest or lock audit does not prove that dependency installation is required for the final image or that an install script is safe to execute.",
    }
    RESULT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
