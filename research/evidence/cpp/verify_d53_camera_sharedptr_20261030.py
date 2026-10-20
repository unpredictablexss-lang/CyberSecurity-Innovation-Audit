#!/usr/bin/env python3
"""Recompute D53's pinned source replay and verify unchanged A0 candidate rows."""
from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
COMMIT = "35445b57d739a41cb916330935e61f1e83d982ca"
TREE = "2907d1748b46897c49c8f8c253c49384294a6a7a"
IDS = {f"CR-{i:04d}" for i in range(261, 291)}


def git(git_dir: str, *args: str) -> str:
    return subprocess.check_output(["git", f"--git-dir={git_dir}", *args], text=True).strip()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source-git-dir", required=True)
    args = ap.parse_args()
    git_dir = str(args.source_git_dir)
    if git(git_dir, "cat-file", "-t", COMMIT) != "commit" or git(git_dir, "show", "-s", "--format=%T", COMMIT) != TREE:
        raise SystemExit("FAIL D53: source commit/tree mismatch")

    queue_path = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv"
    with queue_path.open(encoding="utf-8-sig", newline="") as stream:
        queue = list(csv.DictReader(stream))
    selected = {row["queue_id"]: row for row in queue if row["queue_id"] in IDS}
    if len(queue) != 345 or len(selected) != 30 or set(selected) != IDS:
        raise SystemExit("FAIL D53: expected 345 unique A0 rows and 30 selected IDs")
    for qid, row in selected.items():
        if (row["repository"], row["commit"], row["tree"], row["original_status"], row["queue_status"]) != (
            "openharmony/multimedia_camera_framework", COMMIT, TREE, "not_testable", "paused_pending_evidence"
        ):
            raise SystemExit(f"FAIL D53: {qid} source identity or original status changed")

    with tempfile.TemporaryDirectory(prefix="d53-camera-replay-") as tmp:
        replay = Path(tmp) / "replay.json"
        subprocess.check_call([sys.executable, str(HERE / "d53_camera_sharedptr_assessment_20261030.py"),
                               "--source-git-dir", git_dir, "--output", str(replay)], cwd=ROOT)
        fresh = json.loads(replay.read_text(encoding="utf-8"))
    saved = json.loads((HERE / "d53_camera_sharedptr_cli_20261030.json").read_text(encoding="utf-8"))
    assessment = json.loads((HERE / "d53_camera_sharedptr_assessment_20261030.json").read_text(encoding="utf-8"))
    if fresh != saved:
        raise SystemExit("FAIL D53: saved CLI replay differs from live recomputation")
    if (fresh["detector"], fresh["detector_version"], fresh["selected_count"], fresh["unique_files"]) != (
        "ohscanner.cpp.shared_ptr_race", "0.5.1", 30, 13
    ):
        raise SystemExit("FAIL D53: replay metadata/scope mismatch")
    if any(file["parse_status"] != "complete" for file in fresh["files"]):
        raise SystemExit("FAIL D53: selected source parse status changed")
    if sum(len(file["diagnostics"]) for file in fresh["files"]) != 13:
        raise SystemExit("FAIL D53: detector diagnostics count changed")
    matched = sum(any(d["line"] == case["line"] for d in file["diagnostics"])
                  for file in fresh["files"] for case in file["cases"])
    if matched != 10 or assessment["replay_summary"]["a0_lines_with_same_line_candidate"] != matched:
        raise SystemExit("FAIL D53: exact A0-line finding mapping changed")
    if assessment.get("result") != "no_change" or assessment.get("disposition") != "PARTIAL/BLOCK" or assessment.get("a0_status_mutated") is not False:
        raise SystemExit("FAIL D53: assessment classification invalid")
    print("PASS D53: frozen camera commit/tree/blob/SHA bindings revalidated")
    print("PASS D53: 345-row A0 queue retained; CR-0261–CR-0290 statuses unchanged")
    print("PASS D53: current shared_ptr_race 0.5.1 replay recomputed (13 files, complete syntax parse, 13 findings)")
    print("PASS D53: 10 exact A0 lines reproduce; no-change assessment remains PARTIAL/BLOCK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
