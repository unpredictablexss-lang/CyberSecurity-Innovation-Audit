#!/usr/bin/env python3
"""Verify T29 CR-0336 provenance, M2 candidate, and preserved A0 state."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[3]
AUDIT = pathlib.Path(__file__).with_name("t29_wifi_ipc_source_audit_20261020.json")
CLI = pathlib.Path(__file__).with_name("t29_wifi_ipc_candidate_20261020.json")
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--git-dir", required=True)
    parser.add_argument("--queue-json", type=pathlib.Path, default=ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.json")
    args = parser.parse_args()
    doc = json.loads(AUDIT.read_text(encoding="utf-8"))
    report = json.loads(CLI.read_text(encoding="utf-8"))
    queue = json.loads(args.queue_json.read_text(encoding="utf-8"))
    errors: list[str] = []
    commit, tree = doc["source"]["commit"], doc["source"]["tree"]
    if git(args.git_dir, "cat-file", "-t", commit).decode().strip() != "commit":
        errors.append("source commit is not a commit object")
    if git(args.git_dir, "show", "-s", "--format=%T", commit).decode().strip() != tree:
        errors.append("commit root tree does not match audit")
    if git(args.git_dir, "cat-file", "-t", tree).decode().strip() != "tree":
        errors.append("source tree is not a tree object")

    rows = [r for r in queue.get("queue", []) if r.get("queue_id") == "CR-0336"]
    if len(rows) != 1:
        errors.append(f"expected exactly one A0 CR-0336 row, got {len(rows)}")
    else:
        row = rows[0]
        fields = {
            "candidate_id": doc["candidate_id"], "repository": doc["source"]["repository"],
            "commit": commit, "tree": tree, "path": doc["source"]["path"],
            "line": doc["source"]["line"], "blob": doc["source"]["blob"],
            "source_sha256": doc["source"]["sha256"], "original_status": "not_testable",
            "queue_status": "queued_first_batch",
        }
        for key, expected in fields.items():
            if row.get(key) != expected:
                errors.append(f"A0 {key} mismatch: {row.get(key)!r} != {expected!r}")

    for item in doc["related_sources"]:
        EXPECTED[item["path"]] = item["blob"]
    for path, expected_blob in EXPECTED.items():
        actual_blob = git(args.git_dir, "rev-parse", f"{commit}:{path}").decode().strip()
        data = git(args.git_dir, "show", f"{commit}:{path}")
        row = next((x for x in doc["related_sources"] if x["path"] == path), None)
        if path == doc["source"]["path"]:
            row = doc["source"]
        if actual_blob != expected_blob:
            errors.append(f"blob mismatch for {path}: {actual_blob}")
        if row and (len(data) != row["bytes"] or hashlib.sha256(data).hexdigest() != row["sha256"]):
            errors.append(f"byte count or SHA-256 mismatch for {path}")

    candidate = doc["source"]
    source = git(args.git_dir, "show", f"{commit}:{candidate['path']}").decode("utf-8").splitlines()
    if source[candidate["line"] - 1] != "    int ret = reply.WriteRemoteObject(obj);":
        errors.append("candidate line text mismatch")
    stub = "\n".join(source)
    for token in ("GetWifiRemoteInner", "GetWifiRemote(instId)", "reply.WriteRemoteObject(obj)", "ReadInterfaceToken()", "GetDescriptor()"):
        if token not in stub:
            errors.append(f"candidate source lacks {token}")

    runs = report.get("detector_runs", [])
    if len(runs) != 1 or runs[0].get("tool") != "ohscanner.interface.ipc" or runs[0].get("tool_version") != "0.12.12":
        errors.append("CLI detector identity mismatch")
    else:
        run = runs[0]
        if run.get("status") != "completed" or run.get("diagnostic_count") != 1:
            errors.append("CLI run status/count mismatch")
        if report.get("commit") != commit or report.get("git_tree") != tree:
            errors.append("CLI commit/tree mismatch")
        parse = report.get("source_parsing", {}).get("parsing_status", {})
        if parse.get("complete") != 2 or parse.get("partial", 0) != 0:
            errors.append("CLI parse coverage mismatch")
        found = [d for d in run.get("diagnostics", []) if d.get("rule_id") == "ipc.capability.export" and d.get("file") == candidate["path"] and d.get("line") == candidate["line"]]
        if len(found) != 1 or found[0].get("source_sha256") != candidate["sha256"]:
            errors.append("source-bound IPC candidate missing/mismatched")

    print(json.dumps({"ok": not errors, "queue_id": doc["queue_id"], "disposition": doc["disposition"], "original_status": doc["original_status"], "queue_status": doc["queue_status"], "errors": errors}, ensure_ascii=False, indent=2))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
