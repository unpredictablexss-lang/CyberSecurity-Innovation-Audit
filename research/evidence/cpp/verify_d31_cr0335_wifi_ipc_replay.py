#!/usr/bin/env python3
"""Verify D31's CR-0335 source binding, exact IPC replay, and preserved A0 state."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
RECORD = HERE / "d31_cr0335_wifi_ipc_replay_20261022.json"
ALT_BLOB = "6106eb782ab6ffb605ec6ebff9e47ed5df923375"


def git(git_dir: str, *args: str) -> bytes:
    return subprocess.check_output(["git", f"--git-dir={git_dir}", *args], stderr=subprocess.PIPE)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--git-dir", required=True)
    ap.add_argument("--queue", type=Path, required=True)
    ap.add_argument("--cli-json", type=Path, required=True)
    args = ap.parse_args()
    record = json.loads(RECORD.read_text(encoding="utf-8"))
    queue = json.loads(args.queue.read_text(encoding="utf-8"))
    cli = json.loads(args.cli_json.read_text(encoding="utf-8"))
    errors: list[str] = []

    row = next((r for r in queue["queue"] if r["queue_id"] == "CR-0335"), None)
    if row is None:
        errors.append("CR-0335 missing from frozen A0 queue")
    else:
        expected = {
            "candidate_id": record["candidate_id"],
            "original_status": record["original_status"],
            "queue_status": record["queue_status"],
            "commit": record["commit"],
            "tree": record["tree"],
            "blob": record["candidate_source"]["blob"],
            "source_sha256": record["candidate_source"]["sha256"],
        }
        for key, value in expected.items():
            if row.get(key) != value:
                errors.append(f"A0 {key} changed or mismatched: {row.get(key)!r} != {value!r}")

    commit, tree, source = record["commit"], record["tree"], record["candidate_source"]
    if git(args.git_dir, "cat-file", "-t", commit).decode().strip() != "commit":
        errors.append("A0 commit object type invalid")
    if git(args.git_dir, "show", "-s", "--format=%T", commit).decode().strip() != tree:
        errors.append("A0 root tree mismatch")
    if git(args.git_dir, "cat-file", "-t", tree).decode().strip() != "tree":
        errors.append("queue tree object type invalid")
    path = source["path"]
    blob = git(args.git_dir, "rev-parse", f"{commit}:{path}").decode().strip()
    data = git(args.git_dir, "show", f"{commit}:{path}")
    if blob != source["blob"]:
        errors.append(f"candidate blob mismatch: {blob}")
    if hashlib.sha256(data).hexdigest() != source["sha256"]:
        errors.append("candidate SHA-256 mismatch")
    lines = data.decode("utf-8").splitlines()
    if len(lines) < source["candidate_line"] or lines[source["candidate_line"] - 1] != source["candidate_line_text"]:
        errors.append("candidate line text mismatch")
    source_text = "\n".join(lines)
    for required in (
        "if (cfgLen <= 0)", "if (cfgLen > MAX_LEN)", "data.ReadBuffer(cfgLen)",
        "new (std::nothrow) char[cfgLen]", "memcpy_s(cfgData, cfgLen, dataBuffer, cfgLen)",
        "OnConfigChanged(cfgType, cfgData, cfgLen)",
    ):
        if required not in source_text:
            errors.append(f"source guard/helper fact absent: {required}")

    if git(args.git_dir, "cat-file", "-t", ALT_BLOB).decode().strip() != "blob":
        errors.append("alternate task-message blob missing")
    if hashlib.sha256(git(args.git_dir, "cat-file", "blob", ALT_BLOB)).hexdigest() != record["identity_conflict"]["message_sha256"]:
        errors.append("alternate blob does not match recorded message SHA")

    if cli.get("commit") != commit or cli.get("git_tree") != tree:
        errors.append("CLI source commit/tree mismatch")
    if cli.get("scope", {}).get("declared_scope") != [path]:
        errors.append("CLI scope is not the exact A0 candidate file")
    if cli.get("source_parsing", {}).get("parsing_status") != {"complete": 1}:
        errors.append("CLI parse coverage is not complete 1/1")
    runs = [r for r in cli.get("detector_runs", []) if r.get("tool") == "ohscanner.interface.ipc"]
    hits = [d for r in runs for d in r.get("diagnostics", [])
            if d.get("rule_id") == "ipc.parcel.copy-range" and d.get("file") == path and d.get("line") == 385]
    if not hits:
        errors.append("current production IPC replay did not reproduce the queue-line finding")
    elif hits[0].get("source_sha256") != source["sha256"]:
        errors.append("CLI finding source SHA differs from A0 candidate")
    if cli.get("detector_count") != 1:
        errors.append("CLI must select only the production IPC detector")

    result = {"ok": not errors, "record_id": record["record_id"],
              "original_status_preserved": bool(row and row.get("original_status") == "not_reproduced"),
              "queue_status_preserved": bool(row and row.get("queue_status") == "queued_not_reproduced"),
              "exact_source_and_cli_candidate_verified": not errors, "errors": errors}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
