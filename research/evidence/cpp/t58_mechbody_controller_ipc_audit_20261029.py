#!/usr/bin/env python3
"""Replay T58's pinned mechbody controller IPC candidates and preserve A0 labels."""
from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
SOURCE = pathlib.Path(r"D:\openHarmonyScanner\tmp\t58-mechbody-source-20261029")
OUT = pathlib.Path(r"D:\openHarmonyScanner\tmp\t58-mechbody-ipc-20261029.json")
MD_OUT = pathlib.Path(r"D:\openHarmonyScanner\tmp\t58-mechbody-ipc-20261029.md")
EXPECTED = json.loads(pathlib.Path(__file__).with_suffix(".json").read_text(encoding="utf-8"))
QUEUE = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv"

def main() -> int:
    rows = {}
    import csv
    with QUEUE.open(encoding="utf-8-sig", newline="") as stream:
        rows = {row["queue_id"]: row for row in csv.DictReader(stream)}
    expected_ids = {item["id"] for item in EXPECTED["a0_rows"]}
    assert expected_ids <= rows.keys()
    for item in EXPECTED["a0_rows"]:
        row = rows[item["id"]]
        assert row["original_status"] == item["original_status"]
        assert row["queue_status"] == item["queue_status"]
        assert row["repository"] == EXPECTED["repository"]
        assert row["commit"] == EXPECTED["commit"]
        assert row["tree"] == EXPECTED["git_tree"]
        assert row["path"] == item["path"] and int(row["line"]) == item["line"]
        blob = subprocess.check_output(["git", "-C", str(SOURCE), "rev-parse", f"{EXPECTED['commit']}:{item['path']}"], text=True).strip()
        data = subprocess.check_output(["git", "-C", str(SOURCE), "cat-file", "blob", blob])
        assert blob == item["blob"] and hashlib.sha256(data).hexdigest() == item["sha256"]

    command = [sys.executable, "-m", "src.cli.main", "ohscan-run", "--repo-dir", str(SOURCE),
               "--repository", EXPECTED["repository"], "--commit", EXPECTED["commit"],
               "--detector", EXPECTED["detector"]]
    for item in EXPECTED["a0_rows"]:
        command.extend(["--include", item["path"]])
    command.extend(["--json-out", str(OUT), "--md-out", str(MD_OUT)])
    subprocess.run(command, cwd=ROOT, check=True)
    report = json.loads(OUT.read_text(encoding="utf-8"))
    assert report["git_tree"] == EXPECTED["git_tree"]
    run = next(item for item in report["detector_runs"] if item["tool"] == EXPECTED["detector"])
    found = {(item["file"], item["line"]): item for item in run["diagnostics"]}
    assert len(found) == 3
    for item in EXPECTED["a0_rows"]:
        diagnostic = found[(item["path"], item["line"])]
        assert diagnostic["diagnostic_id"] == item["candidate_id"]
        assert diagnostic["source_sha256"] == item["sha256"]
    assert all(next(p for p in run["parsing"] if p["file"] == item["path"])["status"] == "complete" for item in EXPECTED["a0_rows"])
    print(json.dumps({"ok": True, "a0_rows_preserved": 3, "diagnostics": 3, "parse": "complete", "validated_vulnerabilities": 0}, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())


