#!/usr/bin/env python3
"""Capture recursively declared Ninja inputs and output bytes for active headers."""
from __future__ import annotations

import argparse
import hashlib
import json
import posixpath
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict, deque
from pathlib import Path, PurePosixPath
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from bind_active_closure_producers import parse_edges  # noqa: E402


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_oid(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def project_map(path: Path) -> dict[str, str]:
    root = ET.parse(path).getroot()
    return {
        (p.attrib.get("path") or p.attrib.get("name")): p.attrib["revision"]
        for p in root.findall("project")
        if (p.attrib.get("path") or p.attrib.get("name")) and p.attrib.get("revision")
    }


def project_for(path: str, projects: dict[str, str]) -> str | None:
    matches = [p for p in projects if path == p or path.startswith(p + "/")]
    return max(matches, key=len) if matches else None


def resolve(token: str, source: Path, output: Path, prebuilts: Path,
            toolchain: Path) -> tuple[str, Path, str]:
    if token.startswith("../../prebuilts/clang/ohos/linux-x86_64/llvm/"):
        suffix = token.removeprefix("../../prebuilts/clang/ohos/linux-x86_64/llvm/")
        root = toolchain / "clang_linux-x86_64-02fbe8-20260908"
        return "toolchain", root / PurePosixPath(suffix), "toolchain/clang_linux-x86_64-02fbe8-20260908/" + suffix
    if token.startswith("../../prebuilts/"):
        rel = posixpath.normpath(token.removeprefix("../../prebuilts/"))
        return "prebuilt", prebuilts / PurePosixPath(rel), "prebuilts/" + rel
    if token.startswith("../../"):
        rel = posixpath.normpath(token[6:])
        return "manifest_source", source / PurePosixPath(rel), rel
    if token.startswith("/src/out/rk3568/"):
        rel = token.removeprefix("/src/out/rk3568/")
        return "generated_output", output / PurePosixPath(rel), "out/rk3568/" + rel
    if token.startswith("/src/"):
        rel = token.removeprefix("/src/")
        return "manifest_source", source / PurePosixPath(rel), rel
    if token.startswith("/toolchain/"):
        rel = token.removeprefix("/toolchain/")
        return "toolchain", toolchain / PurePosixPath(rel), "toolchain/" + rel
    if token.startswith(("gen/", "obj/", "clang_x64/", "clang_arm64/")):
        return "generated_output", output / PurePosixPath(token), "out/rk3568/" + token
    return "unclassified", output / PurePosixPath(token), "out/rk3568/" + token


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--report", required=True, type=Path)
    ap.add_argument("--ninja-graph", required=True, type=Path)
    ap.add_argument("--source-root", required=True, type=Path)
    ap.add_argument("--output-root", required=True, type=Path)
    ap.add_argument("--prebuilts-root", required=True, type=Path)
    ap.add_argument("--toolchain-root", required=True, type=Path)
    ap.add_argument("--resolved-manifest", required=True, type=Path)
    ap.add_argument("--project-git-dirs", required=True, type=Path)
    ap.add_argument("--workspace-root", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    ns = ap.parse_args()

    report = json.loads(ns.report.read_text(encoding="utf-8"))
    graph_bytes = ns.ninja_graph.read_bytes()
    graph_text = graph_bytes.decode("utf-8", "replace")
    lines = graph_text.splitlines()
    edges = parse_edges(graph_text)
    source, output = ns.source_root.resolve(), ns.output_root.resolve()
    prebuilts, toolchain = ns.prebuilts_root.resolve(), ns.toolchain_root.resolve()
    projects = project_map(ns.resolved_manifest)
    git_dirs = ns.project_git_dirs.resolve()

    direct = report.get("producer_graph", {}).get("direct_active_producer_records", [])
    queue = deque([edge["output"] for edge in direct])
    for edge in direct:
        queue.extend(item["path"] for item in edge["inputs"])
    queue.append("gen/third_party/musl/uapi_files.stamp")

    seen: set[str] = set()
    edge_outputs: dict[int, set[str]] = defaultdict(set)
    edge_rows: dict[int, dict[str, Any]] = {}
    output_files: dict[str, dict[str, Any]] = {}
    leaves: dict[str, dict[str, Any]] = {}
    unresolved: list[dict[str, Any]] = []
    ambiguous: list[str] = []
    while queue:
        token = queue.popleft()
        if token in seen:
            continue
        seen.add(token)
        candidates = edges.get(token, [])
        if candidates:
            if len(candidates) != 1:
                ambiguous.append(token)
                continue
            edge = candidates[0]
            line_no = edge["line"]
            edge_outputs[line_no].add(token)
            if line_no not in edge_rows:
                rule_line = next((i for i, line in enumerate(lines[:line_no - 1]) if line == "rule " + edge["rule"]), None)
                command_line = None if rule_line is None else next(
                    (line for line in lines[rule_line + 1:rule_line + 8] if line.startswith("  command = ")), None
                )
                edge_rows[line_no] = {
                    "line": line_no,
                    "rule": edge["rule"],
                    "raw_line_sha256": sha256(edge["raw"].encode("utf-8")),
                    "command": command_line.removeprefix("  command = ") if command_line else None,
                    "inputs": edge["inputs"],
                }
            out_class, out_path, logical = resolve(token, source, output, prebuilts, toolchain)
            try:
                if out_path.is_file():
                    data = out_path.read_bytes()
                    output_files[token] = {
                        "logical_path": logical,
                        "bytes": len(data),
                        "sha256": sha256(data),
                        "rule": edge["rule"],
                    }
                elif out_path.is_dir():
                    output_files[token] = {"logical_path": logical, "kind": "directory", "rule": edge["rule"]}
                elif edge["rule"] != "phony":
                    unresolved.append({"path": token, "reason": "producer output file or directory missing", "rule": edge["rule"]})
            except OSError as exc:
                unresolved.append({"path": token, "reason": f"{type(exc).__name__}: {exc}", "rule": edge["rule"]})
            queue.extend(item["path"] for item in edge["inputs"])
            continue

        kind, path, logical = resolve(token, source, output, prebuilts, toolchain)
        try:
            data = path.read_bytes()
        except OSError as exc:
            if path.is_dir():
                # Directory-copy actions are separately enumerated and source-blob checked.
                leaves[token] = {"logical_path": logical, "class": kind, "kind": "directory_input", "path": str(path)}
            else:
                unresolved.append({"path": token, "resolved_path": str(path), "reason": f"{type(exc).__name__}: {exc}"})
            continue
        row: dict[str, Any] = {"logical_path": logical, "class": kind, "bytes": len(data), "sha256": sha256(data)}
        if kind == "manifest_source":
            row["git_blob_oid_computed"] = git_blob_oid(data)
            project = project_for(logical, projects)
            if project is None:
                row["origin_status"] = "unmapped_manifest_path"
            else:
                row["project_path"] = project
                row["project_commit"] = projects[project]
                row["project_relative_path"] = logical[len(project):].lstrip("/")
                row["origin_status"] = "pin_check_pending"
        else:
            row["origin_status"] = "content_hashed"
        leaves[token] = row

    # Verify source file blobs in one cat-file batch per pinned project.
    by_project: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for token, row in leaves.items():
        if row.get("class") == "manifest_source" and row.get("project_path"):
            by_project[row["project_path"]].append((token, row))
    for project, project_rows in by_project.items():
        db = git_dirs / (project + ".git")
        refs = [f"{row['project_commit']}:{row['project_relative_path']}" for _, row in project_rows]
        check = subprocess.run(
            ["git", f"--git-dir={db}", "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
            input=("\n".join(refs) + "\n").encode("utf-8"), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False,
        )
        outputs = check.stdout.decode("ascii", "replace").splitlines()
        for index, (_, row) in enumerate(project_rows):
            fields = outputs[index].split() if index < len(outputs) else []
            row["origin_status"] = (
                "verified_pinned_git_blob"
                if not check.returncode and len(fields) == 3 and fields[1] == "blob"
                and fields[0] == row["git_blob_oid_computed"] and int(fields[2]) == row["bytes"]
                else "pinned_blob_missing_or_mismatch"
            )
            if row["origin_status"] != "verified_pinned_git_blob":
                row["git_check_output"] = fields
                unresolved.append({"path": row["logical_path"], "reason": row["origin_status"], "project": project})

    for token, row in leaves.items():
        if row.get("class") == "manifest_source" and row.get("origin_status") != "verified_pinned_git_blob":
            if not row.get("project_path"):
                unresolved.append({"path": row["logical_path"], "reason": row.get("origin_status")})

    edge_records = []
    for line_no, row in sorted(edge_rows.items()):
        row["outputs"] = [
            {"path": path, **output_files[path]}
            for path in sorted(edge_outputs[line_no]) if path in output_files
        ]
        edge_records.append(row)

    status_counts: dict[str, int] = defaultdict(int)
    for row in leaves.values():
        status_counts[row.get("origin_status", "unknown")] += 1
    capture = {
        "schema": "ohscanner.c4.generated-input-graph-closure/v1",
        "status": "verified_declared_generated_input_graph_closure" if not unresolved and not ambiguous else "blocked_generated_input_graph_gaps",
        "ninja_graph_path": str(ns.ninja_graph),
        "ninja_graph_bytes": len(graph_bytes),
        "ninja_graph_sha256": sha256(graph_bytes),
        "active_generated_root_count": len(direct),
        "recursive_producer_edge_count": len(edge_rows),
        "recursive_producer_output_count": len(output_files),
        "unique_node_count": len(seen),
        "terminal_input_count": len(leaves),
        "terminal_input_origin_status_counts": dict(sorted(status_counts.items())),
        "pinned_project_count": len(by_project),
        "producer_edges": edge_records,
        "terminal_inputs": [leaves[key] | {"ninja_path": key} for key in sorted(leaves)],
        "unresolved": unresolved,
        "ambiguous_outputs": sorted(ambiguous),
        "limits": [
            "Covers recursively declared Ninja inputs reachable from the two selected ARM actions' generated-header producers.",
            "Directory outputs from Musl GN actions are handled by the separate UAPI side-effect evidence, which binds active copied headers byte-identically to pinned sources.",
            "Does not claim a successful full product build or globally valid Ninja graph; duplicate-output diagnostics remain separate.",
        ],
    }
    ns.output.write_text(json.dumps(capture, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    if capture["status"] == "verified_declared_generated_input_graph_closure":
        producer_graph = report.get("producer_graph", {})
        side_effects = producer_graph.get("musl_uapi_declared_action_side_effects", {})
        producer_count = len(producer_graph.get("direct_active_producer_records", []))
        active_count = producer_graph.get("active_generated_outputs", 0)
        if (side_effects.get("verified_side_effect_count") == 12
                and not side_effects.get("failures")
                and not side_effects.get("unresolved_graph_gaps")
                and producer_count + side_effects["verified_side_effect_count"] == active_count):
            report_path = ns.output.resolve().relative_to(ns.workspace_root.resolve()).as_posix()
            report["producer_graph"]["recursive_input_closure"] = {
                "path": report_path,
                "bytes": ns.output.stat().st_size,
                "sha256": sha256(ns.output.read_bytes()),
                "recursive_producer_edge_count": capture["recursive_producer_edge_count"],
                "recursive_producer_output_count": capture["recursive_producer_output_count"],
                "terminal_input_count": capture["terminal_input_count"],
                "terminal_input_origin_status_counts": capture["terminal_input_origin_status_counts"],
                "status": capture["status"],
            }
            report["producer_graph"]["producer_unbound_active_outputs"] = []
            report["producer_graph"]["missing_producer_outputs"] = []
            report["producer_graph"]["transitive_input_content_binding"] = "verified for all recursively declared Ninja producer inputs"
            report["status"] = "verified_active_generated_input_closure"
            report["generated_or_tool_inputs_require_producer_evidence"] = False
            ns.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({
        "status": capture["status"],
        "recursive_producer_edge_count": capture["recursive_producer_edge_count"],
        "recursive_producer_output_count": capture["recursive_producer_output_count"],
        "terminal_input_count": capture["terminal_input_count"],
        "terminal_input_origin_status_counts": capture["terminal_input_origin_status_counts"],
        "unresolved_count": len(unresolved),
        "ambiguous_count": len(ambiguous),
    }, ensure_ascii=False, indent=2))
    return 0 if capture["status"] == "verified_declared_generated_input_graph_closure" else 2


if __name__ == "__main__":
    raise SystemExit(main())
