#!/usr/bin/env python3
"""Verify D25 CR-0013..0015 source identities, original queue state and CLI replays."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


COMMIT = "560c5cdadf08b4beeb691e93d70ff32cc2dca8bd"
TREE = "f731230c116c94d7619f5514c828b33ffac69924"
QUEUE_IDS = {"CR-0013", "CR-0014", "CR-0015"}
TARGETS = {
    "frameworks/native/provider/include/datashare_stub_impl.h": (
        "b3cc65d4a39b596cad57477e30e06bc7a673b37c",
        "81df12f7bf672ed146509837fc73c7ad857237d08f47cb4af54341311ebc284c",
    ),
    "frameworks/native/provider/src/datashare_stub_impl.cpp": (
        "4ef431998b11042ce96e449eacf4dbd14549d764",
        "77f46f95b78da2bd329dd202f8006368efa1f555854f157e273c3b257d9048eb",
    ),
    "frameworks/native/provider/include/datashare_uv_queue.h": (
        "d10ef5bfce76280182053b7f64ef7fc903b0bb30",
        "e80606dc89f948be432b95140848c5eb9d84e574d30eae069714e2b8f79ce2b1",
    ),
    "frameworks/native/provider/src/datashare_uv_queue.cpp": (
        "1338265507cb31cd3233a67dc9c3f3c078ed7008",
        "577f0c93ed8354cd3f9dd3e6b740c7989d76644c7199fe5ed4c1bf4ef1df67fc",
    ),
}
HERE = Path(__file__).resolve().parent


def git(git_dir: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", f"--git-dir={git_dir}", *args])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-git-dir", type=Path, required=True)
    parser.add_argument("--queue-json", type=Path, required=True)
    args = parser.parse_args()
    git_dir = args.source_git_dir.resolve()
    queue = json.loads(args.queue_json.read_text(encoding="utf-8"))["queue"]
    rows = {row["queue_id"]: row for row in queue if row["queue_id"] in QUEUE_IDS}
    if set(rows) != QUEUE_IDS:
        raise SystemExit("A0 rows missing or duplicated")
    if git(git_dir, "rev-parse", f"{COMMIT}^{{commit}}").decode().strip() != COMMIT:
        raise SystemExit("pinned commit mismatch")
    if git(git_dir, "show", "-s", "--format=%T", COMMIT).decode().strip() != TREE:
        raise SystemExit("pinned tree mismatch")
    expected_lines = {"CR-0013": 35, "CR-0014": 40, "CR-0015": 42}
    for queue_id, row in rows.items():
        if row["commit"] != COMMIT or row["tree"] != TREE:
            raise SystemExit(f"{queue_id}: queue commit/tree mismatch")
        if row["original_status"] != "not_testable" or row["queue_status"] != "paused_pending_evidence":
            raise SystemExit(f"{queue_id}: original status changed")
        if row["line"] != expected_lines[queue_id]:
            raise SystemExit(f"{queue_id}: line mismatch")
        data = git(git_dir, "show", f"{COMMIT}:{row['path']}")
        blob = git(git_dir, "rev-parse", f"{COMMIT}:{row['path']}").decode().strip()
        if blob != row["blob"] or hashlib.sha256(data).hexdigest() != row["source_sha256"]:
            raise SystemExit(f"{queue_id}: source object/hash mismatch")
        text = data.decode("utf-8").splitlines()
        expected_text = row["original_record"]["source_binding"]["line_text"].strip()
        if expected_text not in text[row["line"] - 1]:
            raise SystemExit(f"{queue_id}: source line binding mismatch")

    for path, (expected_blob, expected_sha) in TARGETS.items():
        data = git(git_dir, "show", f"{COMMIT}:{path}")
        blob = git(git_dir, "rev-parse", f"{COMMIT}:{path}").decode().strip()
        if blob != expected_blob or hashlib.sha256(data).hexdigest() != expected_sha:
            raise SystemExit(f"supporting source identity mismatch: {path}")

    header = json.loads((HERE / "d25_shared_ptr_cr0013_15_header_20261020.json").read_text(encoding="utf-8"))
    bounded = json.loads((HERE / "d25_shared_ptr_cr0013_15_bounded_20261020.json").read_text(encoding="utf-8"))
    for label, report in (("header", header), ("bounded", bounded)):
        if report["commit"] != COMMIT or report["git_tree"] != TREE:
            raise SystemExit(f"{label}: replay provenance mismatch")
        if len(report["detector_runs"]) != 1:
            raise SystemExit(f"{label}: unexpected detector count")
        run = report["detector_runs"][0]
        if (run["tool"], run["tool_version"]) != ("ohscanner.cpp.shared_ptr_race", "0.5.1"):
            raise SystemExit(f"{label}: detector identity mismatch")
        if label == "header":
            if report["source_parsing"]["parsing_status"] != {"complete": 1}:
                raise SystemExit("header replay is not fully parsed")
            diagnostics = run["diagnostics"]
            if [(d["file"], d["line"], d["symbol"]) for d in diagnostics] != [
                ("frameworks/native/provider/include/datashare_stub_impl.h", 35, "uvQueue_"),
                ("frameworks/native/provider/include/datashare_stub_impl.h", 42, "uvQueue_"),
            ]:
                raise SystemExit("header replay candidate mapping changed")
        elif run["diagnostic_count"] != 2:
            raise SystemExit("bounded replay candidate count changed")

    print("D25 pinned source commit/tree and CR-0013..0015 queue bindings/statuses: PASS")
    print("D25 header and bounded CLI replay provenance/results: PASS")
    print("D25 supporting implementation and queue source identities: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
