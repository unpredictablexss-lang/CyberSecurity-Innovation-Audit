#!/usr/bin/env python3
"""Export exact Git trees from a resolved OpenHarmony repo manifest to a new directory."""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath
from typing import Any

EXPECTED_MANIFEST_SHA256 = "52f528dada321a140a29be2d55ef9053fda818cbdca93758425f1a25f6286d55"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
SCHEMA = "ohscanner.c1.clean-manifest-git-archive/v1"
REPORT_PATH: Path | None = None


def safe_rel(raw: str, label: str) -> PurePosixPath:
    path = PurePosixPath(raw)
    if not raw or path.is_absolute() or ".." in path.parts or "\\" in raw:
        raise ValueError(f"unsafe {label}: {raw!r}")
    return path


def run_git(repo: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ).stdout


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temp, path)


def archive_tree(source: Path, revision: str, destination: Path, workspace: Path,
                 overlay_nested: bool = False) -> dict[str, Any]:
    tree = run_git(source, "rev-parse", f"{revision}^{{tree}}").decode().strip()
    entries = run_git(source, "ls-tree", "-r", "-z", revision).split(b"\0")
    gitlinks = []
    for entry in entries:
        if not entry:
            continue
        header, raw_path = entry.split(b"\t", 1)
        mode, kind, oid = header.decode("ascii").split()
        if mode == "160000" and kind == "commit":
            gitlinks.append({"path": raw_path.decode("utf-8", "surrogateescape"), "commit": oid})

    relative = destination.relative_to(workspace)
    cursor = workspace
    for part in relative.parts[:-1]:
        cursor = cursor / part
        if cursor.is_symlink():
            raise RuntimeError(f"project destination crosses a symlink: {cursor}")
    if destination.exists() or destination.is_symlink():
        if not overlay_nested:
            raise FileExistsError(f"destination already exists: {destination}")
        if destination.is_symlink() or not destination.is_dir():
            destination.unlink()
        else:
            shutil.rmtree(destination)
    destination.mkdir(parents=True, exist_ok=True)

    archive = subprocess.Popen(
        ["git", "-C", str(source), "archive", "--format=tar", revision],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    assert archive.stdout is not None
    extractor = subprocess.Popen(
        ["tar", "--extract", "--file=-", "--directory", str(destination),
         "--no-same-owner", "--same-permissions"],
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    assert extractor.stdin is not None
    digest = hashlib.sha256()
    byte_count = 0
    try:
        while True:
            chunk = archive.stdout.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            byte_count += len(chunk)
            extractor.stdin.write(chunk)
        extractor.stdin.close()
    except BaseException:
        extractor.kill()
        archive.kill()
        raise
    archive.stdout.close()
    tar_error = extractor.stderr.read() if extractor.stderr else b""
    git_error = archive.stderr.read() if archive.stderr else b""
    tar_code = extractor.wait()
    git_code = archive.wait()
    if git_code or tar_code:
        raise RuntimeError(
            f"archive failed for {source} at {revision}: git={git_code} tar={tar_code}; "
            f"git stderr={git_error[-2000:]!r}; tar stderr={tar_error[-2000:]!r}"
        )
    return {
        "commit": revision,
        "tree": tree,
        "archive_tar_sha256": digest.hexdigest(),
        "archive_tar_bytes": byte_count,
        "git_tree_entries": sum(bool(entry) for entry in entries),
        "gitlinks": gitlinks,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--resolved-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args()

    source_root = args.source_root.resolve()
    manifest_path = args.resolved_manifest.resolve()
    output = args.output.absolute()
    if args.workers < 1 or args.workers > 16:
        raise ValueError("workers must be between 1 and 16")
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"output must be a new path: {output}")

    manifest_bytes = manifest_path.read_bytes()
    manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
    if manifest_sha != EXPECTED_MANIFEST_SHA256:
        raise ValueError(f"resolved manifest SHA-256 mismatch: {manifest_sha}")
    root = ET.fromstring(manifest_bytes)
    projects = []
    linkfiles = []
    for project in root.findall("project"):
        name = project.get("name")
        raw_path = project.get("path") or name
        revision = project.get("revision", "")
        if not name or not HEX40.fullmatch(revision):
            raise ValueError(f"manifest project lacks a pinned commit: {ET.tostring(project, encoding='unicode')}")
        project_path = safe_rel(raw_path or "", "project path")
        projects.append({"name": name, "path": project_path.as_posix(), "revision": revision})
        for link in project.findall("linkfile"):
            src = link.get("src", "")
            src_path = PurePosixPath(".") if src == "." else safe_rel(src, "link source")
            dest = safe_rel(link.get("dest", ""), "link destination")
            linkfiles.append({"project": project_path.as_posix(), "src": src_path.as_posix(), "dest": dest.as_posix()})
        if project.findall("copyfile"):
            raise ValueError("resolved manifest contains copyfile directives; exporter only implements linkfile")

    paths = [p["path"] for p in projects]
    if len(paths) != len(set(paths)):
        raise ValueError("resolved manifest has duplicate project paths")
    by_path = {p["path"]: p for p in projects}
    output.mkdir(parents=True)
    (output / ".repo").mkdir(parents=True)
    (output / ".repo" / "manifest.xml").write_bytes(manifest_bytes)
    report: dict[str, Any] = {
        "schema": SCHEMA,
        "status": "running",
        "resolved_manifest": {"path": str(manifest_path), "sha256": manifest_sha,
                              "bytes": len(manifest_bytes), "projects": len(projects)},
        "source_root": str(source_root),
        "output_root": str(output),
        "workers": args.workers,
        "manifest_repository": None,
        "projects": [],
        "linkfiles": [],
        "unresolved_gitlinks": [],
    }
    report_path = output / "materialization_manifest.json"
    global REPORT_PATH
    REPORT_PATH = report_path
    atomic_json(report_path, report)

    # The repo manifest checkout supplies product matrix/config files not stored in project repos.
    manifests_repo = source_root / ".repo" / "manifests"
    manifests_commit = run_git(manifests_repo, "rev-parse", "HEAD").decode().strip()
    report["manifest_repository"] = archive_tree(
        manifests_repo, manifests_commit, output / ".repo" / "manifests", output
    ) | {"commit": manifests_commit, "path": ".repo/manifests"}
    atomic_json(report_path, report)

    nested_paths = {p for p in paths if any(p.startswith(parent.rstrip("/") + "/") for parent in paths)}
    levels: dict[int, list[dict[str, str]]] = {}
    for project in projects:
        depth = len(PurePosixPath(project["path"]).parts)
        levels.setdefault(depth, []).append(project)
    records: dict[str, dict[str, Any]] = {}
    for depth in sorted(levels):
        batch = levels[depth]
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {}
            for project in batch:
                rel = PurePosixPath(project["path"])
                source = source_root.joinpath(*rel.parts)
                dest = output.joinpath(*rel.parts)
                futures[pool.submit(archive_tree, source, project["revision"], dest, output,
                                    project["path"] in nested_paths)] = project
            for future in concurrent.futures.as_completed(futures):
                project = futures[future]
                record = future.result()
                record.update({"name": project["name"], "path": project["path"]})
                records[project["path"]] = record
                report["projects"] = [records[p] for p in sorted(records)]
                atomic_json(report_path, report)

    for project_path, record in records.items():
        for gitlink in record["gitlinks"]:
            nested = (PurePosixPath(project_path) / gitlink["path"]).as_posix()
            expected = by_path.get(nested)
            if expected is None or expected["revision"] != gitlink["commit"]:
                report["unresolved_gitlinks"].append({"project": project_path, **gitlink})

    for link in linkfiles:
        src = output.joinpath(*PurePosixPath(link["project"]).parts, *PurePosixPath(link["src"]).parts)
        dest = output.joinpath(*PurePosixPath(link["dest"]).parts)
        if not src.exists() and not src.is_symlink():
            raise FileNotFoundError(f"manifest linkfile source missing: {src}")
        if dest.exists() or dest.is_symlink():
            raise FileExistsError(f"manifest linkfile destination already exists: {dest}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        target = os.path.relpath(src, dest.parent)
        os.symlink(target, dest, target_is_directory=src.is_dir())
        report["linkfiles"].append({**link, "target": target})

    if report["unresolved_gitlinks"]:
        report["status"] = "blocked_unresolved_gitlinks"
    else:
        report["status"] = "complete_git_tree_export_lfs_audit_pending"
    atomic_json(report_path, report)
    print(json.dumps({"status": report["status"], "projects": len(records),
                      "linkfiles": len(linkfiles), "manifest_sha256": manifest_sha,
                      "report": str(report_path)}, ensure_ascii=False, indent=2))
    return 0 if report["status"].startswith("complete") else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        if REPORT_PATH is not None and REPORT_PATH.exists():
            try:
                report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
                report["status"] = "failed"
                report["error"] = str(exc)
                atomic_json(REPORT_PATH, report)
            except Exception:
                pass
        print(f"materialization failed: {exc}", file=sys.stderr)
        raise
