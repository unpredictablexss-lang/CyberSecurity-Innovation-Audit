#!/usr/bin/env python3
"""Capture and verify byte identities for C1's two compiler dependency files.

This tool is read-only. It resolves Clang -M paths against the exact source,
GN output, prebuilts, and compiler package roots. Source inputs are checked
against the manifest-pinned project Git blob; generated/tool inputs are
content-hashed and retain their GN output/tool-package classification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import posixpath
import re
import shlex
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Any


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_oid(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def git_dir_for(root: Path, project_path: str) -> Path:
    return root / (project_path + ".git")


def parse_depfile(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    text = re.sub(r"\\\r?\n\s*", " ", text)
    _, separator, prerequisites = text.partition(":")
    if not separator:
        raise ValueError(f"depfile has no target separator: {path}")
    return shlex.split(prerequisites, posix=True)


def resolve_dependency(token: str, source_root: Path, output_root: Path,
                       prebuilts_root: Path, toolchain_root: Path) -> tuple[str, Path, str]:
    if token.startswith("../../prebuilts/"):
        rel = posixpath.normpath(token[len("../../prebuilts/"):])
        llvm_prefix = "clang/ohos/linux-x86_64/llvm/"
        if rel.startswith(llvm_prefix):
            suffix = rel[len(llvm_prefix):]
            compiler_root = toolchain_root / "clang_linux-x86_64-02fbe8-20260908"
            return "compiler_toolchain", compiler_root / PurePosixPath(suffix), "toolchain/clang_linux-x86_64-02fbe8-20260908/" + suffix
        return "prebuilt_toolchain", prebuilts_root / PurePosixPath(rel), "prebuilts/" + rel
    if token.startswith("../../"):
        rel = posixpath.normpath(token[6:])
        return "manifest_source", source_root / PurePosixPath(rel), rel
    if token.startswith("/toolchain/"):
        rel = token[len("/toolchain/"):]
        return "compiler_toolchain", toolchain_root / PurePosixPath(rel), "toolchain/" + rel
    if token.startswith(("gen/", "obj/", "clang_x64/", "clang_arm64/")):
        return "generated_or_output", output_root / PurePosixPath(token), "out/rk3568/" + token
    if token.startswith("/"):
        return "unmapped_absolute", Path(token), token
    return "unclassified_relative", output_root / PurePosixPath(token), "out/rk3568/" + token


def manifest_projects(path: Path) -> dict[str, str]:
    root = ET.parse(path).getroot()
    projects = {
        (item.attrib.get("path") or item.attrib.get("name")): item.attrib["revision"]
        for item in root.findall("project")
        if (item.attrib.get("path") or item.attrib.get("name")) and item.attrib.get("revision")
    }
    return projects


def longest_project(path: str, projects: dict[str, str]) -> str | None:
    matches = [key for key in projects if path == key or path.startswith(key + "/")]
    return max(matches, key=len) if matches else None


def verify_git_sources(rows: list[dict[str, Any]], projects: dict[str, str],
                       project_git_dirs: Path) -> None:
    by_project: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        if row["class"] != "manifest_source":
            continue
        project = longest_project(row["logical_path"], projects)
        if project is None:
            row["origin_status"] = "unmapped_manifest_path"
            continue
        row["project_path"] = project
        row["project_commit"] = projects[project]
        row["project_relative_path"] = row["logical_path"][len(project):].lstrip("/")
        by_project[project].append(row)

    for project, project_rows in by_project.items():
        git_dir = git_dir_for(project_git_dirs, project)
        if not git_dir.is_dir():
            for row in project_rows:
                row["origin_status"] = "project_object_database_missing"
            continue
        refs = [f"{row['project_commit']}:{row['project_relative_path']}" for row in project_rows]
        result = subprocess.run(
            ["git", f"--git-dir={git_dir}", "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
            input=("\n".join(refs) + "\n").encode("utf-8"),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        if result.returncode:
            error = result.stderr.decode("utf-8", "replace")[:500]
            for row in project_rows:
                row["origin_status"] = "git_batch_failed"
                row["git_error"] = error
            continue
        outputs = result.stdout.decode("ascii", "replace").splitlines()
        for row, output in zip(project_rows, outputs):
            fields = output.split()
            if len(fields) != 3 or fields[1] != "blob":
                row["origin_status"] = "pinned_blob_missing_or_not_blob"
                continue
            row["git_blob_oid"] = fields[0]
            row["git_blob_bytes"] = int(fields[2])
            row["origin_status"] = (
                "verified_pinned_git_blob"
                if fields[0] == row["git_blob_oid_computed"] and int(fields[2]) == row["bytes"]
                else "pinned_blob_byte_mismatch"
            )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--depfile", action="append", required=True, type=Path)
    ap.add_argument("--source-root", required=True, type=Path)
    ap.add_argument("--output-root", required=True, type=Path)
    ap.add_argument("--prebuilts-root", required=True, type=Path)
    ap.add_argument("--toolchain-root", required=True, type=Path)
    ap.add_argument("--resolved-manifest", required=True, type=Path)
    ap.add_argument("--project-git-dirs", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    ns = ap.parse_args()

    source_root = ns.source_root.resolve()
    output_root = ns.output_root.resolve()
    prebuilts_root = ns.prebuilts_root.resolve()
    toolchain_root = ns.toolchain_root.resolve()
    projects = manifest_projects(ns.resolved_manifest)
    by_token: dict[str, set[str]] = defaultdict(set)
    for depfile in ns.depfile:
        for token in parse_depfile(depfile):
            by_token[token].add(depfile.name)

    rows: list[dict[str, Any]] = []
    for token, actions in sorted(by_token.items()):
        kind, path, logical_path = resolve_dependency(token, source_root, output_root, prebuilts_root, toolchain_root)
        row: dict[str, Any] = {
            "spelling": token,
            "logical_path": logical_path,
            "class": kind,
            "actions": sorted(actions),
        }
        try:
            data = path.read_bytes()
        except OSError as exc:
            row.update({"origin_status": "missing", "error": f"{type(exc).__name__}: {exc}"})
        else:
            row.update({"bytes": len(data), "sha256": sha256(data), "origin_status": "content_hashed"})
            if kind == "manifest_source":
                row["git_blob_oid_computed"] = git_blob_oid(data)
        rows.append(row)

    verify_git_sources(rows, projects, ns.project_git_dirs.resolve())
    status_counts: dict[str, int] = defaultdict(int)
    class_counts: dict[str, int] = defaultdict(int)
    for row in rows:
        status_counts[row["origin_status"]] += 1
        class_counts[row["class"]] += 1
    result = {
        "schema": "ohscanner.c4.active-include-closure/v1",
        "status": (
            "blocked" if any(value not in {"verified_pinned_git_blob", "content_hashed"} for value in status_counts)
            else "located_source_bytes_verified_generated_producer_binding_pending"
            if any(row["class"] == "generated_or_output" for row in rows)
            else "source_and_tool_bytes_verified"
        ),
        "depfiles": [
            {"path": str(path), "sha256": sha256(path.read_bytes()), "bytes": path.stat().st_size}
            for path in sorted(ns.depfile)
        ],
        "action_count": len(ns.depfile),
        "unique_dependency_count": len(rows),
        "class_counts": dict(sorted(class_counts.items())),
        "origin_status_counts": dict(sorted(status_counts.items())),
        "generated_or_tool_inputs_require_producer_evidence": True,
        "dependencies": rows,
    }
    ns.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({key: result[key] for key in (
        "status", "action_count", "unique_dependency_count", "class_counts", "origin_status_counts"
    )}, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "verified" else 2


if __name__ == "__main__":
    raise SystemExit(main())
