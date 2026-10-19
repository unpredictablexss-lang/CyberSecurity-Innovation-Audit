#!/usr/bin/env python3
"""Verify T54 CR-0336 source provenance, current CLI replay, and frozen A0 state."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[3]
AUDIT = ROOT / "research/evidence/cpp/t29_wifi_ipc_source_audit_20261020.json"
CLI = ROOT / "research/evidence/cpp/t54_wifi_cr0336_current_cli_20261027.json"
QUEUE = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.json"
EXPECTED = {
    "wifi/services/wifi_standard/wifi_framework/wifi_manage/wifi_sta_sa/wifi_device_mgr_stub.cpp": "6106eb782ab6ffb605ec6ebff9e47ed5df923375",
    "wifi/services/wifi_standard/wifi_framework/wifi_manage/wifi_sta_sa/wifi_device_mgr_service_impl.cpp": "6764cab322c82d860905316ace540f839816f7bf",
    "wifi/services/wifi_standard/sa_profile/1120.json": "443352b2ca7b14b0fa3c7641641f99157199219a",
    "wifi/frameworks/native/interfaces/i_wifi_device.h": "2b80cb7e2c014c2a3abc6b0e88ca65166c5cee05",
    "wifi/frameworks/native/src/wifi_device_mgr_proxy.cpp": "02bffe5db40d5b4968cc52f791744ae222771810",
    "wifi/services/wifi_standard/wifi_framework/wifi_manage/wifi_sta_sa/wifi_device_stub.cpp": "fc32789e244b4caf80aba734bb51404096f93770",
    "wifi/services/wifi_standard/wifi_framework/wifi_manage/wifi_sta_sa/wifi_device_service_impl.cpp": "e87d25c4d79a7d40d16e73a908883c3076db182a",
}


def git(git_dir: str, *args: str) -> bytes:
    return subprocess.check_output(["git", f"--git-dir={git_dir}", *args], stderr=subprocess.PIPE)


def load(path: pathlib.Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--git-dir", required=True, help="communication_wifi object database")
    parser.add_argument("--queue-json", type=pathlib.Path, default=QUEUE)
    args = parser.parse_args()
    audit, report, queue = load(AUDIT), load(CLI), load(args.queue_json)
    errors: list[str] = []
    source = audit["source"]
    commit, tree = source["commit"], source["tree"]
    if git(args.git_dir, "cat-file", "-t", commit).decode().strip() != "commit":
        errors.append("pinned source commit is missing")
    if git(args.git_dir, "show", "-s", "--format=%T", commit).decode().strip() != tree:
        errors.append("pinned source tree mismatch")
    rows = [row for row in queue.get("queue", []) if row.get("queue_id") == "CR-0336"]
    if len(rows) != 1:
        errors.append(f"expected exactly one CR-0336 A0 row, got {len(rows)}")
    else:
        row = rows[0]
        for key, expected in {
            "candidate_id": audit["candidate_id"], "repository": source["repository"],
            "commit": commit, "tree": tree, "path": source["path"], "line": source["line"],
            "blob": source["blob"], "source_sha256": source["sha256"],
            "original_status": "not_testable", "queue_status": "queued_first_batch",
        }.items():
            if row.get(key) != expected:
                errors.append(f"A0 {key} mismatch: {row.get(key)!r} != {expected!r}")
    related = {item["path"]: item for item in audit["related_sources"]}
    related[source["path"]] = source
    for path, expected_blob in EXPECTED.items():
        try:
            blob = git(args.git_dir, "rev-parse", f"{commit}:{path}").decode().strip()
            data = git(args.git_dir, "show", f"{commit}:{path}")
        except subprocess.CalledProcessError:
            errors.append(f"missing source object: {path}")
            continue
        if blob != expected_blob:
            errors.append(f"blob mismatch for {path}: {blob}")
        item = related.get(path)
        if item and (len(data) != item["bytes"] or hashlib.sha256(data).hexdigest() != item["sha256"]):
            errors.append(f"byte count/SHA-256 mismatch for {path}")

    if report.get("commit") != commit or report.get("git_tree") != tree or report.get("status") != "completed":
        errors.append("current CLI commit/tree/status mismatch")
    if report.get("source_parsing", {}).get("parsing_status", {}).get("complete") != 2:
        errors.append("current CLI did not completely parse both selected files")
    runs = report.get("detector_runs", [])
    if len(runs) != 1:
        errors.append("expected one detector run")
    else:
        run = runs[0]
        if (run.get("tool"), run.get("tool_version"), run.get("status"), run.get("diagnostic_count")) != (
            "ohscanner.interface.ipc", "0.12.12", "completed", 1
        ):
            errors.append("current IPC detector identity/status/count mismatch")
        found = [d for d in run.get("diagnostics", []) if d.get("rule_id") == "ipc.capability.export"
                 and d.get("file") == source["path"] and d.get("line") == source["line"]
                 and d.get("source_sha256") == source["sha256"]]
        if len(found) != 1:
            errors.append("current source-bound ipc.capability.export candidate missing")
    result = {"ok": not errors, "queue_id": "CR-0336", "disposition": "PARTIAL/BLOCK",
              "original_status": "not_testable", "queue_status": "queued_first_batch", "errors": errors}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
