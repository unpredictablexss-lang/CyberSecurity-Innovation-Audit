"""Output-blind syntax census for the pinned ETS Frontend LSP source frame.

Reads only Git blobs from the manifest-pinned commit and the syntax-only
Tree-sitter frontend. It never imports or invokes C-line detector code.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
MANIFEST = HERE / "blind_manifest.json"
CENSUS = HERE / "component_census.json"
SOURCE_PREFIX = "ets2panda/lsp/src/"
EXTENSIONS = (".cpp", ".cc", ".cxx")
sys.path.insert(0, str(ROOT))
from research.full_scan_20261018.lanes.c.syntax import parse_functions, walk  # noqa: E402


def git(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.PIPE)


def build_census(repo: Path) -> dict:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    source = manifest["source"]
    commit, expected_tree = source["commit"], source["tree"]
    resolved = git(repo, "rev-parse", f"{commit}^{{tree}}").decode().strip()
    if resolved != expected_tree:
        raise SystemExit(f"pinned tree mismatch: {resolved}")
    entries = git(repo, "ls-tree", "-r", "-z", "--full-tree", commit).split(b"\0")
    rows = []
    for entry in entries:
        if not entry:
            continue
        metadata, raw_path = entry.split(b"\t", 1)
        mode, kind, oid = metadata.decode("ascii").split()
        path = raw_path.decode("utf-8")
        if kind != "blob" or not path.startswith(SOURCE_PREFIX) or not path.endswith(EXTENSIONS):
            continue
        data = git(repo, "cat-file", "blob", oid)
        try:
            tree, functions = parse_functions(data)
            errors = sum(node.type in ("ERROR", "MISSING") for node in walk(tree.root_node))
            parse_status = "partial" if tree.root_node.has_error else "complete"
        except (UnicodeDecodeError, ValueError, RuntimeError):
            functions, errors, parse_status = [], None, "failed"
        rows.append({
            "path": path,
            "mode": mode,
            "blob_oid": oid,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "parse_status": parse_status,
            "parse_error_or_missing_nodes": errors,
            "function_definitions": len(functions),
        })
    rows.sort(key=lambda row: row["path"])
    census = {
        "schema": "c-line-ets-frontend-lsp-syntax-census-v1",
        "provenance": {
            "repository": source["repository"],
            "commit": commit,
            "tree": expected_tree,
            "subtree": SOURCE_PREFIX,
            "selection": "all tracked C++ translation units in the pinned subtree; syntax only; detector output not consulted",
        },
        "files": rows,
        "summary": {
            "tracked_cpp_files": len(rows),
            "complete_files": sum(row["parse_status"] == "complete" for row in rows),
            "partial_files": sum(row["parse_status"] == "partial" for row in rows),
            "failed_files": sum(row["parse_status"] == "failed" for row in rows),
            "function_definitions": sum(row["function_definitions"] for row in rows),
            "function_definitions_in_complete_files": sum(
                row["function_definitions"] for row in rows if row["parse_status"] == "complete"
            ),
        },
    }
    manifest["component_census"] = {
        "artifact": "research/deliveries/cpp/holdout-arkcompiler-ets-frontend-fadba67/component_census.json",
        **census["summary"],
        "sampled_translation_units": 1,
        "sampled_complete_cpp_files": 1,
        "sampled_function_excerpts": manifest["selection"]["sample_count_total"],
        "complete_function_coverage_fraction": round(
            manifest["selection"]["sample_count_total"] /
            census["summary"]["function_definitions_in_complete_files"], 6
        ),
        "frame_interpretation": "current 21 excerpts are clustered in one complete translation unit; they do not form a component-wide representative sample",
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8", newline="\n")
    return census


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: python build_component_census.py <local-git-repository>")
    census = build_census(Path(sys.argv[1]).resolve())
    CENSUS.write_text(json.dumps(census, indent=2, ensure_ascii=False) + "\n",
                      encoding="utf-8", newline="\n")
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    manifest["component_census"]["census_sha256"] = hashlib.sha256(CENSUS.read_bytes()).hexdigest()
    MANIFEST.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8", newline="\n")
    print(json.dumps(census["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
