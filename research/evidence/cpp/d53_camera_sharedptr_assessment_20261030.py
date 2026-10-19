#!/usr/bin/env python3
"""Replay current shared_ptr_race on frozen camera A0 source files."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.cpp.shared_ptr_race_detector import SharedPtrRaceDetector
from src.ohscanner.fixture import snapshot_digest
from src.parser.ast import parse_source

COMMIT = "35445b57d739a41cb916330935e61f1e83d982ca"
TREE = "2907d1748b46897c49c8f8c253c49384294a6a7a"
REPOSITORY = "openharmony/multimedia_camera_framework"
IDS = {f"CR-{i:04d}" for i in range(261, 291)}
QUEUE = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv"


def git(git_dir: str, *args: str) -> bytes:
    return subprocess.check_output(["git", f"--git-dir={git_dir}", *args], stderr=subprocess.PIPE)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source-git-dir", required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    git_dir = str(args.source_git_dir)
    if git(git_dir, "cat-file", "-t", COMMIT).decode().strip() != "commit":
        raise SystemExit("frozen source commit is unavailable")
    if git(git_dir, "show", "-s", "--format=%T", COMMIT).decode().strip() != TREE:
        raise SystemExit("frozen source tree mismatch")

    with QUEUE.open(encoding="utf-8-sig", newline="") as stream:
        queue = list(csv.DictReader(stream))
    selected = {r["queue_id"]: r for r in queue if r["queue_id"] in IDS}
    if len(queue) != 345 or set(selected) != IDS:
        raise SystemExit("A0 queue count/selection mismatch")

    # Bind every row and analyze each distinct source file once, preserving its exact source identity.
    source_rows: dict[str, dict] = {}
    for qid, row in selected.items():
        if (row["repository"], row["commit"], row["tree"], row["original_status"], row["queue_status"]) != (
            REPOSITORY, COMMIT, TREE, "not_testable", "paused_pending_evidence"
        ):
            raise SystemExit(f"{qid}: frozen A0 binding/state mismatch")
        path = row["path"]
        raw = git(git_dir, "show", f"{COMMIT}:{path}")
        blob = git(git_dir, "rev-parse", f"{COMMIT}:{path}").decode().strip()
        sha = hashlib.sha256(raw).hexdigest()
        if (blob, sha) != (row["blob"], row["source_sha256"]):
            raise SystemExit(f"{qid}: source blob/SHA mismatch")
        lines = raw.decode("utf-8").splitlines()
        if int(row["line"]) > len(lines):
            raise SystemExit(f"{qid}: A0 line outside source")
        case = source_rows.setdefault(path, {"path": path, "blob": blob, "sha256": sha,
                                             "bytes": len(raw), "cases": [], "lines": lines})
        case["cases"].append({"queue_id": qid, "line": int(row["line"]),
                              "line_text": lines[int(row["line"]) - 1],
                              "candidate_id": row["candidate_id"],
                              "original_status": row["original_status"],
                              "queue_status": row["queue_status"]})

    detector = SharedPtrRaceDetector()
    runs = []
    for path, source in sorted(source_rows.items()):
        text = git(git_dir, "show", f"{COMMIT}:{path}").decode("utf-8")
        source.pop("lines")
        index = parse_source(text, language="cpp")
        unit = SourceUnit(path, "cpp", text, source["sha256"], index.parse_status,
                          tuple(str(issue) for issue in index.parse_issues))
        units = (unit,)
        request = ScanRequest(f"D53-{path}", REPOSITORY, COMMIT, snapshot_digest(units),
                              f"current-component:{REPOSITORY}", "light-ast", "git_object")
        run = detector.detect(ScanContext(request, units, {"ast": {path: index.to_dict()}}), units)
        source.update({"parse_status": unit.parse_status,
                       "parse_issues": list(unit.parse_issues),
                       "diagnostics": [{"line": f.line, "rule_id": f.rule_id,
                                        "message": f.message}
                                       for f in run.findings]})
        runs.append(source)

    result = {"schema_version": 1, "task": "D53", "repository": REPOSITORY,
              "commit": COMMIT, "git_tree": TREE, "detector": detector.detector_id,
              "detector_version": detector.version, "profile": "light-ast",
              "build_profile": "none", "a0_row_count": len(queue), "selected_ids": sorted(IDS),
              "selected_count": len(selected), "unique_files": len(runs),
              "files": runs,
              "limitations": ["Selected-source lexical/AST replay only; no product build or macro expansion.",
                              "No global CFG, alias, thread, lifecycle, product inclusion or runtime proof.",
                              "Diagnostics are candidates; zero findings are not safety evidence."]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    nfind = sum(len(file["diagnostics"]) for file in runs)
    ncomplete = sum(file["parse_status"] == "complete" for file in runs)
    print(f"D53 CLI replay: {len(selected)} A0 rows, {len(runs)} files, {ncomplete} complete, {nfind} diagnostics; {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
