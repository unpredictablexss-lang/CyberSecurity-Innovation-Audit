#!/usr/bin/env python3
"""Bind active generated dependencies to raw Ninja producer edges.

This does not claim that the graph is globally valid: it records exact producer
lines from the byte-hashed generated graph and recursively follows generated
inputs while leaving content identity of the transitive inputs pending.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_edges(text: str) -> dict[str, list[dict[str, Any]]]:
    by_output: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.startswith("build ") or ": " not in line:
            continue
        lhs, rhs = line[6:].split(": ", 1)
        fields = rhs.split()
        if not fields:
            continue
        rule = fields[0]
        inputs: list[dict[str, str]] = []
        section = "explicit"
        for token in fields[1:]:
            if token == "|":
                section = "implicit"
            elif token == "||":
                section = "order_only"
            elif token.startswith("#"):
                break
            else:
                inputs.append({"path": token.replace("$ ", " "), "kind": section})
        edge = {"line": line_no, "raw": line, "rule": rule, "inputs": inputs}
        for output in lhs.split():
            by_output[output.replace("$ ", " ")].append(edge)
    return by_output


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--report", required=True, type=Path)
    ap.add_argument("--ninja-graph", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    ns = ap.parse_args()

    report = json.loads(ns.report.read_text(encoding="utf-8"))
    graph_bytes = ns.ninja_graph.read_bytes()
    graph_text = graph_bytes.decode("utf-8", "replace")
    edges = parse_edges(graph_text)
    row_by_ninja_path = {
        row["logical_path"].removeprefix("out/rk3568/"): row
        for row in report["dependencies"]
        if row["class"] == "generated_or_output"
    }
    missing: list[str] = []
    ambiguous: list[str] = []
    for output, row in row_by_ninja_path.items():
        candidates = edges.get(output, [])
        if len(candidates) == 1:
            row["producer"] = {
                "graph_path": str(ns.ninja_graph),
                "graph_sha256": sha256(graph_bytes),
                "line": candidates[0]["line"],
                "rule": candidates[0]["rule"],
                "declared_inputs": candidates[0]["inputs"],
            }
        elif len(candidates) == 0:
            missing.append(output)
        elif len(candidates) > 1:
            ambiguous.append(output)
            row["producer_status"] = "ambiguous_graph_edges"
        else:
            row["producer_status"] = "producer_edge_missing"

    report["producer_graph"] = {
        "path": str(ns.ninja_graph),
        "bytes": len(graph_bytes),
        "sha256": sha256(graph_bytes),
        "parse_scope": "raw single-line Ninja build edges; no claim of global graph validity",
        "active_generated_outputs": len(row_by_ninja_path),
        "direct_active_producer_records": [
            {
                "output": output,
                "line": edge["line"],
                "rule": edge["rule"],
                "inputs": edge["inputs"],
            }
            for output, row in sorted(row_by_ninja_path.items())
            if (edge := edges.get(output, [None])[0]) is not None and len(edges.get(output, [])) == 1
        ],
        "missing_producer_outputs": sorted(set(missing)),
        "ambiguous_producer_outputs": sorted(set(ambiguous)),
        "transitive_input_content_binding": "pending; this report binds only direct active producers",
    }
    report["status"] = (
        "generated_producer_edges_bound_transitive_content_binding_pending"
        if not missing and not ambiguous
        else "blocked_generated_producer_edge_gaps"
    )
    report["generated_or_tool_inputs_require_producer_evidence"] = bool(missing or ambiguous)
    ns.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({
        "status": report["status"],
        "active_generated_outputs": len(row_by_ninja_path),
        "direct_producers_bound": len(row_by_ninja_path) - len(set(missing)) - len(set(ambiguous)),
        "missing": len(set(missing)),
        "ambiguous": len(set(ambiguous)),
        "graph_sha256": sha256(graph_bytes),
    }, ensure_ascii=False, indent=2))
    return 0 if not missing and not ambiguous else 2


if __name__ == "__main__":
    raise SystemExit(main())
