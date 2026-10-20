#!/usr/bin/env python3
"""Verify D26 pinned Preferences source, A0 rows and production M2 replays."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

COMMIT = "bff9efd79afc0d7d1ed22a63ff355f1600404596"
TREE = "7761d9e273ae7007046ae115797f255e554523ae"
PATH = "frameworks/js/napi/common/include/js_proxy.h"
BLOB = "abdd7b2ce3f69528bdaf7234746ca335f329485e"
SHA256 = "1109ad9bb63edf57c6fd22558cc87b98fea9692889bca6ec4c75269b83339958"
HERE = Path(__file__).resolve().parent


def git(git_dir: Path, *args: str, data: bytes | None = None) -> bytes:
    return subprocess.check_output(["git", f"--git-dir={git_dir}", *args], input=data)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-git-dir", type=Path, required=True)
    parser.add_argument("--queue-json", type=Path, required=True)
    args = parser.parse_args()
    git_dir = args.source_git_dir.resolve()
    commit = git(git_dir, "rev-parse", COMMIT + "^{commit}").decode().strip()
    tree = git(git_dir, "show", "-s", "--format=%T", commit).decode().strip()
    if (commit, tree) != (COMMIT, TREE):
        raise SystemExit(f"source commit/tree mismatch: {commit} {tree}")
    source = git(git_dir, "show", f"{COMMIT}:{PATH}")
    blob = git(git_dir, "hash-object", "--stdin", data=source).decode().strip()
    sha = hashlib.sha256(source).hexdigest()
    if (blob, sha) != (BLOB, SHA256):
        raise SystemExit(f"source blob/SHA mismatch: {blob} {sha}")

    queue = json.loads(args.queue_json.read_text(encoding="utf-8"))["queue"]
    rows = {row["queue_id"]: row for row in queue if row.get("queue_id") in {"CR-0020", "CR-0021"}}
    if set(rows) != {"CR-0020", "CR-0021"}:
        raise SystemExit("frozen A0 row set mismatch")
    expected_lines = {"CR-0020": 37, "CR-0021": 42}
    for queue_id, line in expected_lines.items():
        row = rows[queue_id]
        expected = (COMMIT, TREE, PATH, line, BLOB, SHA256, "not_testable", "paused_pending_evidence")
        actual = (row["commit"], row["tree"], row["path"], row["line"], row["blob"],
                  row["source_sha256"], row["original_status"], row["queue_status"])
        if actual != expected:
            raise SystemExit(f"{queue_id} queue binding/status mismatch: {actual}")

    expected_paths = {
        "d26_preferences_header_20261020.json": {PATH},
        "d26_preferences_bounded_20261020.json": {
            PATH,
            "frameworks/js/napi/preferences/src/napi_preferences.cpp",
            "frameworks/js/napi/sendable_preferences/src/napi_preferences.cpp",
        },
    }
    for name, paths in expected_paths.items():
        result = json.loads((HERE / name).read_text(encoding="utf-8"))
        if (result["commit"], result["git_tree"], result["repository"]) != (
            COMMIT, TREE, "openharmony/distributeddatamgr_preferences"
        ):
            raise SystemExit(f"{name} source identity mismatch")
        if set(result["scope"]["declared_scope"]) != paths:
            raise SystemExit(f"{name} scope mismatch")
        if result["source_parsing"]["parsing_status"] != {"complete": len(paths)}:
            raise SystemExit(f"{name} parser coverage not complete")
        run = result["detector_runs"][0]
        diagnostics = run["diagnostics"]
        got = {(item["file"], item["line"], item["symbol"]) for item in diagnostics}
        wanted = {(PATH, 37, "instance_"), (PATH, 42, "instance_")}
        if (run["tool"], run["tool_version"], run["status"], got) != (
            "ohscanner.cpp.shared_ptr_race", "0.5.1", "completed", wanted
        ):
            raise SystemExit(f"{name} detector output mismatch: {got}")
        if any(item["source_sha256"] != SHA256 for item in diagnostics):
            raise SystemExit(f"{name} finding source hash mismatch")

    print("D26 source commit/tree/blob/SHA: PASS")
    print("D26 CR-0020/0021 exact A0 rows and unchanged statuses: PASS")
    print("D26 header and bounded M2 replay identities, coverage and findings: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
