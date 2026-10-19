#!/usr/bin/env python3
"""Verify D24 source objects, frozen A0 rows, and captured CLI replay summaries."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
from pathlib import Path


COMMIT = "560c5cdadf08b4beeb691e93d70ff32cc2dca8bd"
TREE = "f731230c116c94d7619f5514c828b33ffac69924"
IDS = {f"CR-{number:04d}" for number in range(5, 13)}
HERE = Path(__file__).resolve().parent


def git(git_dir: Path, *args: str, data: bytes | None = None) -> bytes:
    return subprocess.check_output(
        ["git", f"--git-dir={git_dir}", *args], input=data
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-git-dir", type=Path, required=True,
                        help="bare/local Git object database for the pinned component")
    parser.add_argument("--queue-csv", type=Path, required=True,
                        help="read-only original A0 queue.csv")
    args = parser.parse_args()
    git_dir = args.source_git_dir.resolve()
    queue_csv = args.queue_csv.resolve()

    commit = git(git_dir, "rev-parse", COMMIT + "^{commit}").decode().strip()
    tree = git(git_dir, "show", "-s", "--format=%T", commit).decode().strip()
    if commit != COMMIT or tree != TREE:
        raise SystemExit(f"pinned commit/tree mismatch: {commit} {tree}")

    queue_rows = {
        row["queue_id"]: row
        for row in csv.DictReader(queue_csv.open(encoding="utf-8-sig", newline=""))
        if row["queue_id"] in IDS
    }
    evidence = json.loads((HERE / "d24_datashare_race_20261020.json").read_text(encoding="utf-8"))
    if set(queue_rows) != IDS or {row["queue_id"] for row in evidence["queue_rows"]} != IDS:
        raise SystemExit("A0 queue/evidence row set mismatch")
    for saved in evidence["queue_rows"]:
        row = queue_rows[saved["queue_id"]]
        for key in ("candidate_id", "repository", "commit", "tree", "path", "line", "blob",
                    "source_sha256", "original_status", "queue_status"):
            if row[key] != saved[key]:
                raise SystemExit(f"{saved['queue_id']} A0 field mismatch: {key}")
        blob = git(git_dir, "rev-parse", f"{COMMIT}:{saved['path']}").decode().strip()
        contents = git(git_dir, "show", f"{COMMIT}:{saved['path']}")
        actual_blob = git(git_dir, "hash-object", "--stdin", data=contents).decode().strip()
        actual_sha = hashlib.sha256(contents).hexdigest()
        if blob != saved["blob"] or actual_blob != saved["blob"]:
            raise SystemExit(f"{saved['queue_id']} Git blob mismatch: {blob}")
        if actual_sha != saved["source_sha256"]:
            raise SystemExit(f"{saved['queue_id']} source SHA mismatch: {actual_sha}")
        if row["original_status"] != "not_testable" or row["queue_status"] != "paused_pending_evidence":
            raise SystemExit(f"{saved['queue_id']} status changed in original queue")

    for replay in evidence["cli_replays"]:
        result = json.loads((HERE / Path(replay["path"]).name).read_text(encoding="utf-8"))
        run = result["detector_runs"][0]
        if result["commit"] != COMMIT or result["git_tree"] != TREE:
            raise SystemExit(f"replay source binding mismatch: {replay['path']}")
        if run["tool"] != "ohscanner.cpp.shared_ptr_race" or run["tool_version"] != "0.5.1":
            raise SystemExit(f"unexpected detector identity: {replay['path']}")
        if run["diagnostic_count"] != replay["diagnostic_count"]:
            raise SystemExit(f"diagnostic count mismatch: {replay['path']}")
        if result["source_parsing"]["parsing_status"] != replay["coverage_counts"]:
            raise SystemExit(f"parse coverage mismatch: {replay['path']}")

    print("D24 source commit/tree: PASS")
    print("D24 CR-0005..0012 source blobs/SHA and unchanged A0 states: PASS")
    print("D24 two CLI replay summaries/source bindings: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
