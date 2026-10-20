#!/usr/bin/env python3
"""Verify D33's pinned cJSON CLI replay and unchanged A0 queue."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
from pathlib import Path

COMMIT = "0c2c9dff82cc85539c8362132d7a5f6bf7d1e748"
TREE = "0d8e50cc18f9ae178e9969eed40f8a0c94fb3856"
SOURCES = {
    "cJSON.c": ("152b2caa479c9f448001652913c980a6dafb82e0", "427c72055ae68467b451599f36da074351a5ca53f6e103cd30064e32cf0fffbb", 80529),
    "cJSON_Utils.c": ("8fa24f8e9bf452cf1ba49d1325c85423ce742c74", "bf3092696763a9a446c39365d7c35f23e5acfdca1bd1da33ef66c1161f9243e9", 40736),
}


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--source-git-dir", type=Path, required=True)
    p.add_argument("--queue", type=Path, required=True)
    p.add_argument("--cli-json", type=Path, required=True)
    p.add_argument("--baseline", type=Path, help="optional baseline queue.csv for byte-for-byte comparison")
    a = p.parse_args()
    repo = a.source_git_dir.resolve()
    assert git(repo, "rev-parse", f"{COMMIT}^{{tree}}") == TREE
    for name, (blob, digest, nbytes) in SOURCES.items():
        assert git(repo, "rev-parse", f"{COMMIT}:{name}") == blob
        data = subprocess.check_output(["git", "-C", str(repo), "cat-file", "blob", f"{COMMIT}:{name}"])
        assert len(data) == nbytes and hashlib.sha256(data).hexdigest() == digest
    d = json.loads(a.cli_json.read_text(encoding="utf-8"))
    assert d["commit"] == COMMIT and d["git_tree"] == TREE
    assert d["snapshot_sha256"] == "84452a40925b94a82d038150157e5a3514289d21ea9562bc58d1e202b98b537e"
    assert d["scope"]["declared_scope"] == ["cJSON.c", "cJSON_Utils.c"]
    assert d["scope"]["selected_source_files"] == 2
    assert d["source_parsing"]["parsing_status"] == {"complete": 1, "partial": 1}
    run = d["detector_runs"][0]
    assert (run["tool"], run["tool_version"], run["status"]) == ("ohscanner.cpp.resource_lifetime", "0.4.2", "blocked")
    assert run["diagnostic_count"] == 3
    found = {(x["file"], x["line"], x["rule_id"], x["source_sha256"]) for x in run["diagnostics"]}
    assert ("cJSON.c", 3161, "ohcpp-resource-exhaustion-recursive-compare-cost-candidate-005", SOURCES["cJSON.c"][1]) in found
    assert ("cJSON_Utils.c", 932, "ohcpp-resource-exhaustion-tree-amplification-candidate-004", SOURCES["cJSON_Utils.c"][1]) in found
    assert ("cJSON_Utils.c", 950, "ohcpp-resource-exhaustion-tree-amplification-candidate-004", SOURCES["cJSON_Utils.c"][1]) in found
    rows = list(csv.DictReader(a.queue.open(encoding="utf-8-sig", newline="")))
    assert len(rows) == 345 and len({r["queue_id"] for r in rows}) == 345
    if a.baseline:
        assert sha(a.queue) == sha(a.baseline), "A0 queue differs from supplied baseline"
    print("PASS: source commit/tree, both blob and SHA-256 identities")
    print("PASS: production M2 CLI 0.4.2, two-file scope, coverage, and all three candidate locations")
    print(f"PASS: A0 queue has {len(rows)} unique rows; statuses left unchanged by this evidence-only replay")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
