#!/usr/bin/env python3
"""Verify C1 Musl UAPI headers emitted as declared GN action side effects."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def blob_oid(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--report", required=True, type=Path)
    ap.add_argument("--ninja-graph", required=True, type=Path)
    ap.add_argument("--source-root", required=True, type=Path)
    ap.add_argument("--output-root", required=True, type=Path)
    ap.add_argument("--resolved-manifest", required=True, type=Path)
    ap.add_argument("--project-git-dirs", required=True, type=Path)
    ap.add_argument("--stamp", required=True, type=Path)
    ap.add_argument("--stamp-copy", required=True, type=Path)
    ap.add_argument("--workspace-root", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    ns = ap.parse_args()

    report = json.loads(ns.report.read_text(encoding="utf-8"))
    graph_bytes = ns.ninja_graph.read_bytes()
    graph_lines = graph_bytes.decode("utf-8", "replace").splitlines()
    edge_line = next((i for i, line in enumerate(graph_lines) if line.startswith("build gen/third_party/musl/uapi_files.stamp:")), None)
    if edge_line is None:
        raise SystemExit("GN UAPI stamp producer edge missing")
    edge_tokens = graph_lines[edge_line].split(": ", 1)[1].split()
    if not edge_tokens:
        raise SystemExit("GN UAPI stamp edge has no rule name")
    rule_name = edge_tokens[0]
    rule_line = next((i for i, line in enumerate(graph_lines[:edge_line]) if line == "rule " + rule_name), None)
    if rule_line is None:
        raise SystemExit("GN UAPI stamp edge's rule definition missing")
    command_line = next((line for line in graph_lines[rule_line + 1:rule_line + 8] if line.startswith("  command = ")), None)
    if command_line is None:
        raise SystemExit("GN UAPI stamp command missing near output edge")
    command = command_line.removeprefix("  command = ")
    expected_command_parts = [
        "third_party/musl/scripts/generate_uapi.py",
        "--musl-uapi-dir /src/kernel/linux/patches/linux-5.10/prebuilts/usr/include",
        "--musl-linux-kernel-dir /src/kernel/linux/linux-5.10",
        "--target-cpu arm",
        "--uapi-file-list /src/out/rk3568/gen/third_party/musl/uapi_files.stamp",
        "--output-uapi /src/out/rk3568/obj/third_party/musl/usr/include/arm-linux-ohos",
    ]
    if not all(part in command for part in expected_command_parts):
        raise SystemExit("GN UAPI stamp command differs from expected evaluated ARM action")

    copy_edge_line = next((i for i, line in enumerate(graph_lines) if line.startswith(
        "build obj/third_party/musl/usr/include/arm-linux-ohos/asm: copy "
    )), None)
    if copy_edge_line is None:
        raise SystemExit("GN ARM asm directory-copy edge missing")
    copy_edge = graph_lines[copy_edge_line]
    if "../../kernel/linux/patches/linux-5.10/prebuilts/usr/include/asm-arm/asm" not in copy_edge:
        raise SystemExit("GN ARM asm directory-copy source differs from expected pinned UAPI source")

    stamp_bytes = ns.stamp.read_bytes()
    stamp_text = stamp_bytes.decode("utf-8", "replace")
    if not stamp_text.startswith(
        "UAPI_FROM:local\nUAPI_DIR:/src/kernel/linux/patches/linux-5.10/prebuilts/usr/include\nUAPI_FILES:\n"
    ):
        raise SystemExit("UAPI stamp does not record the expected local pinned source directory")
    ns.stamp_copy.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ns.stamp, ns.stamp_copy)

    projects = {
        (p.attrib.get("path") or p.attrib.get("name")): p.attrib["revision"]
        for p in ET.parse(ns.resolved_manifest).getroot().findall("project")
        if (p.attrib.get("path") or p.attrib.get("name")) and p.attrib.get("revision")
    }
    project = "kernel/linux/patches"
    commit = projects.get(project)
    if not commit:
        raise SystemExit("resolved manifest pin missing for kernel/linux/patches")
    git_dir = ns.project_git_dirs.resolve() / (project + ".git")
    source_root = ns.source_root.resolve()
    output_root = ns.output_root.resolve()
    uapi_source_root = source_root / "kernel/linux/patches/linux-5.10/prebuilts/usr/include"
    uapi_output_root = output_root / "obj/third_party/musl/usr/include/arm-linux-ohos"

    generated_rows = {
        row["logical_path"].removeprefix("out/rk3568/obj/third_party/musl/usr/include/arm-linux-ohos/"): row
        for row in report["dependencies"]
        if row["class"] == "generated_or_output"
        and row["logical_path"].startswith("out/rk3568/obj/third_party/musl/usr/include/arm-linux-ohos/")
    }
    mapped: list[dict[str, Any]] = []
    failures: list[str] = []
    for rel, row in sorted(generated_rows.items()):
        if rel.startswith("asm/"):
            source_rel = "asm-arm/" + rel
        else:
            source_rel = rel
        if not rel.startswith(("asm-generic/", "asm/", "linux/")):
            continue
        dest = uapi_output_root / rel
        src = uapi_source_root / source_rel
        try:
            dest_bytes, src_bytes = dest.read_bytes(), src.read_bytes()
        except OSError as exc:
            failures.append(f"{rel}: {type(exc).__name__}: {exc}")
            continue
        if sha256(dest_bytes) != row.get("sha256") or dest_bytes != src_bytes:
            failures.append(f"{rel}: generated output differs from captured closure/source bytes")
            continue
        listed_path = "/src/out/rk3568/obj/third_party/musl/usr/include/arm-linux-ohos/" + rel
        if rel.startswith("asm/"):
            if not copy_edge.startswith("build obj/third_party/musl/usr/include/arm-linux-ohos/asm: copy "):
                failures.append(f"{rel}: no declared GN directory-copy producer")
                continue
        elif listed_path not in stamp_text.splitlines():
            failures.append(f"{rel}: not listed in generated UAPI stamp")
            continue
        relative_to_project = "linux-5.10/prebuilts/usr/include/" + source_rel
        ref = f"{commit}:{relative_to_project}"
        check = subprocess.run(
            ["git", f"--git-dir={git_dir}", "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
            input=(ref + "\n").encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        fields = check.stdout.decode("ascii", "replace").strip().split()
        actual_oid = blob_oid(src_bytes)
        if check.returncode or len(fields) != 3 or fields[1] != "blob" or fields[0] != actual_oid or int(fields[2]) != len(src_bytes):
            failures.append(f"{rel}: source not verified against pinned Git blob ({check.stderr.decode('utf-8','replace')[:200]})")
            continue
        mapped.append({
            "generated_output": rel,
            "output_sha256": sha256(dest_bytes),
            "bytes": len(dest_bytes),
            "copy_source_project": project,
            "copy_source_commit": commit,
            "copy_source_path": relative_to_project,
            "copy_source_git_blob_oid": actual_oid,
            "copy_source_sha256": sha256(src_bytes),
            "byte_identical_to_pinned_source": True,
            "producer_evidence": (
                {"kind": "declared_GN_directory_copy_member", "graph_line_number": copy_edge_line + 1, "graph_edge": copy_edge}
                if rel.startswith("asm/")
                else {"kind": "declared_GN_action_stamp_side_effect", "stamp_path": "gen/third_party/musl/uapi_files.stamp", "listed_in_stamp": True}
            ),
        })

    expected_missing = set(report.get("producer_graph", {}).get("missing_producer_outputs", []))
    # The raw graph parser tracks output-relative paths; every graph gap in this class must have an exact source binding.
    graph_gaps_in_scope = {x for x in expected_missing if x.startswith("obj/third_party/musl/usr/include/arm-linux-ohos/")}
    mapped_outputs = {"obj/third_party/musl/usr/include/arm-linux-ohos/" + x["generated_output"] for x in mapped}
    unresolved_gaps = sorted(graph_gaps_in_scope - mapped_outputs)
    if unresolved_gaps:
        failures.extend("unbound raw Ninja gap: " + item for item in unresolved_gaps)

    producer_graph = report.setdefault("producer_graph", {})
    producer_graph["musl_uapi_declared_action_side_effects"] = {
        "action": "third_party/musl:generate_uapi_h",
        "stamp_output": "gen/third_party/musl/uapi_files.stamp",
        "stamp_sha256": sha256(stamp_bytes),
        "stamp_bytes": len(stamp_bytes),
        "evidence_copy_workspace_path": ns.stamp_copy.resolve().relative_to(ns.workspace_root.resolve()).as_posix(),
        "graph_sha256": sha256(graph_bytes),
        "build_edge_line_number": edge_line + 1,
        "build_edge_raw": graph_lines[edge_line],
        "rule_definition_line_number": rule_line + 1,
        "rule_name": rule_name,
        "evaluated_command_line": command,
        "directory_copy_edge_line_number": copy_edge_line + 1,
        "directory_copy_edge_raw": copy_edge,
        "source_project": project,
        "source_commit": commit,
        "verified_side_effect_count": len(mapped),
        "side_effects": mapped,
        "unresolved_graph_gaps": unresolved_gaps,
        "failures": failures,
        "producer_model": "GN action declares a stamp and writes the listed UAPI files as side effects; these are not individual Ninja outputs",
    }
    if not failures and len(mapped) == 12:
        producer_graph["raw_graph_missing_individual_output_edges"] = sorted(expected_missing)
        producer_graph["missing_producer_outputs"] = sorted(set(expected_missing) - graph_gaps_in_scope)
        producer_graph["side_effect_bound_outputs"] = sorted(mapped_outputs)
        producer_graph["producer_unbound_active_outputs"] = []
        producer_graph["transitive_input_content_binding"] = "pending for the directly declared inputs of all active generated outputs"
        report["status"] = "active_generated_producers_bound_transitive_input_content_binding_pending"
        report["generated_or_tool_inputs_require_producer_evidence"] = True
    else:
        report["status"] = "blocked_generated_side_effect_proof_gaps"
        report["generated_or_tool_inputs_require_producer_evidence"] = True
    ns.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({
        "status": report["status"],
        "side_effects_bound": len(mapped),
        "unresolved_graph_gaps": unresolved_gaps,
        "failures": failures,
        "stamp_sha256": sha256(stamp_bytes),
    }, ensure_ascii=False, indent=2))
    return 0 if not failures and len(mapped) == 12 else 2


if __name__ == "__main__":
    raise SystemExit(main())
