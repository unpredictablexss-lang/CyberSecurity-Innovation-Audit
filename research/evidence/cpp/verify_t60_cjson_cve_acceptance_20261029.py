#!/usr/bin/env python3
"""Verify T60's independent cJSON CLI replay, exact sources, controls, and A0 status."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
COMMIT = "0c2c9dff82cc85539c8362132d7a5f6bf7d1e748"
TREE = "0d8e50cc18f9ae178e9969eed40f8a0c94fb3856"
BASE = "8e79a238c3689ec6ffc2d98559a801e1620042ed"
EXPECTED = {
    "cJSON.c": ("152b2caa479c9f448001652913c980a6dafb82e0", "427c72055ae68467b451599f36da074351a5ca53f6e103cd30064e32cf0fffbb", 80529, "partial"),
    "cJSON_Utils.c": ("8fa24f8e9bf452cf1ba49d1325c85423ce742c74", "bf3092696763a9a446c39365d7c35f23e5acfdca1bd1da33ef66c1161f9243e9", 40736, "complete"),
}


def check(ok: bool, message: str) -> None:
    if not ok:
        raise SystemExit("FAIL: " + message)
    print("PASS: " + message)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-git-dir", required=True)
    parser.add_argument("--cli-json", type=Path, default=ROOT / "research/evidence/cpp/t60_cjson_cli_20261029.json")
    parser.add_argument("--controls-json", type=Path, default=ROOT / "research/evidence/cpp/t60_cjson_compare_controls_20261029.json")
    parser.add_argument("--queue", type=Path, default=ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.json")
    args = parser.parse_args()

    def git(*cmd: str, binary: bool = False):
        result = subprocess.check_output(["git", "--git-dir", args.source_git_dir, *cmd])
        return result if binary else result.decode().strip()

    check(git("rev-parse", COMMIT) == COMMIT and git("rev-parse", f"{COMMIT}^{{tree}}") == TREE,
          "component commit and tree resolve exactly")
    for path, (oid, digest, size, _) in EXPECTED.items():
        raw = git("cat-file", "blob", f"{COMMIT}:{path}", binary=True)
        check(git("rev-parse", f"{COMMIT}:{path}") == oid and len(raw) == size and hashlib.sha256(raw).hexdigest() == digest,
              f"{path} Git blob, byte count, and SHA-256 match")

    cli = json.loads(args.cli_json.read_text(encoding="utf-8"))
    check(cli["commit"] == COMMIT and cli["git_tree"] == TREE and cli["scope"]["declared_scope"] == ["cJSON.c", "cJSON_Utils.c"],
          "raw production CLI report binds exact two-file source scope")
    run = cli["detector_runs"][0]
    check(run["tool"] == "ohscanner.cpp.resource_lifetime" and run["tool_version"] == "0.4.2" and run["status"] == "blocked",
          "current detector version and blocked aggregate status are preserved")
    parse = {row["file"]: row["status"] for row in run["parsing"]}
    check(parse == {path: values[3] for path, values in EXPECTED.items()}, "parser state is one partial and one complete")
    observed = {(d["file"], d["line"], d["column"], d["rule_id"], d["source_sha256"]) for d in run["diagnostics"]}
    expected = {
        ("cJSON.c", 3161, 22, "ohcpp-resource-exhaustion-recursive-compare-cost-candidate-005", EXPECTED["cJSON.c"][1]),
        ("cJSON_Utils.c", 932, 13, "ohcpp-resource-exhaustion-tree-amplification-candidate-004", EXPECTED["cJSON_Utils.c"][1]),
        ("cJSON_Utils.c", 950, 9, "ohcpp-resource-exhaustion-tree-amplification-candidate-004", EXPECTED["cJSON_Utils.c"][1]),
    }
    check(observed == expected and cli["detector_coverage"]["detectors"]["ohscanner.cpp.resource_lifetime"]["status"] == "partial",
          "all three line-level candidates, source bindings, and partial coverage match")

    controls = json.loads(args.controls_json.read_text(encoding="utf-8"))
    check(controls["fixed_control"] is False and controls["experimental_patch_commit"] == "bd307ec3b5f1c0555976c4b0118621e485367aa2",
          "develop patch remains explicitly experimental, never called fixed")
    safe = [row for row in controls["cases"] if row["input"].endswith(("safe_recursive_compare_indexed_lookup.c", "safe_recursive_compare_cost.c"))]
    exp = [row for row in controls["cases"] if row["input"].startswith("experimental/")]
    check(len(safe) == 2 and all(not row["findings"] for row in safe) and len(exp) == 1 and not exp[0]["findings"],
          "both safe compare controls and unmerged experiment are quiet in direct-detector replay")

    queue = json.loads(args.queue.read_text(encoding="utf-8-sig"))
    frozen = json.loads(subprocess.check_output(["git", "show", f"{BASE}:research/deliveries/cpp/a0_triage_20261019/queue.json"], cwd=ROOT).decode("utf-8-sig"))
    pair = lambda obj: {row["queue_id"]: (row["original_status"], row["queue_status"]) for row in obj["queue"]}
    check(len(pair(queue)) == 345 and pair(queue) == pair(frozen), "all 345 A0 IDs and status pairs match frozen baseline")
    check("D3's original detector 0.3.0 run" in (ROOT / "research/evidence/cpp/t60_cjson_cve_2026_67215_67216_acceptance_20261029.md").read_text(encoding="utf-8"),
          "human report documents D3 root-separation review and remaining evidence limits")


if __name__ == "__main__":
    main()
