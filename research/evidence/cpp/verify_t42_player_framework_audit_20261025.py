#!/usr/bin/env python3
"""Verify T42's source identity, production CLI mapping and A0 preservation."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
AUDIT = HERE / "t42_player_framework_audit_20261025.json"
CLI = HERE / "t42_player_framework_cli_20261025.json"
COMMIT = "71ab1e0881e0a79f2b9528742677467e7bb8dde5"
TREE = "9cc6c53506a70424485885c4c10b29dfbfaa8d1b"
BASE = "3ce72e3bcbd0bb534a4daab1bd16fa08bf30bc7e"
RULE = "ipc.relay.descriptor-boundary"


def git(git_dir: str, *args: str) -> bytes:
    return subprocess.check_output(["git", f"--git-dir={git_dir}", *args], stderr=subprocess.PIPE)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--git-dir", required=True, help="bare/object-rich local player_framework Git mirror")
    args = ap.parse_args()
    audit = json.loads(AUDIT.read_text(encoding="utf-8"))
    cli = json.loads(CLI.read_text(encoding="utf-8"))
    with (ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv").open(encoding="utf-8-sig", newline="") as f:
        queue = list(csv.DictReader(f))
    target = [r for r in queue if 174 <= int(r["queue_id"].split("-")[1]) <= 196]
    errors: list[str] = []

    def check(ok: bool, message: str) -> None:
        if not ok:
            errors.append(message)

    check(audit.get("audit_id") == "T42", "wrong audit ID")
    check(audit.get("scanner_baseline") == BASE, "scanner baseline must be the requested independent base")
    check(len(target) == 23 and audit.get("a0_row_count") == 23, "A0 group must contain exactly 23 rows")
    check(git(args.git_dir, "cat-file", "-t", COMMIT).decode().strip() == "commit", "component commit object missing")
    check(git(args.git_dir, "show", "-s", "--format=%T", COMMIT).decode().strip() == TREE, "component tree mismatch")
    check(git(args.git_dir, "cat-file", "-t", TREE).decode().strip() == "tree", "component tree object missing")

    by_id = {x.get("queue_id"): x for x in audit.get("per_id", [])}
    check(len(by_id) == 23, "per-ID record count must be 23 unique IDs")
    findings = [d for run in cli.get("detector_runs", []) if run.get("tool") == "ohscanner.interface.ipc" for d in run.get("diagnostics", [])]
    finding_by_pos = {(d.get("file"), d.get("line")): d for d in findings}
    queue_positions = set()
    for row in target:
        qid = row["queue_id"]
        rec = by_id.get(qid)
        check(rec is not None, f"{qid} missing from audit record")
        if rec is None:
            continue
        path, line = row["path"], int(row["line"])
        queue_positions.add((path, line))
        for key, field in (("candidate_id", "candidate_id"), ("commit", "commit"), ("tree", "tree"), ("path", "path"), ("line", "line"), ("blob", "blob"), ("source_sha256", "source_sha256"), ("rule", "rule"), ("original_status", "original_status"), ("queue_status", "queue_status")):
            left, right = rec.get(key), row[field]
            if key == "line":
                left = int(left) if left is not None else None
                right = int(right)
            check(left == right, f"{qid} {key} differs from frozen A0")
        check(row["repository"] == "openharmony/multimedia_player_framework" and row["commit"] == COMMIT and row["tree"] == TREE, f"{qid} A0 repo/commit/tree mismatch")
        raw = git(args.git_dir, "show", f"{COMMIT}:{path}")
        check(git(args.git_dir, "rev-parse", f"{COMMIT}:{path}").decode().strip() == row["blob"], f"{qid} source blob mismatch")
        check(hashlib.sha256(raw).hexdigest() == row["source_sha256"], f"{qid} source SHA-256 mismatch")
        source_lines = raw.decode("utf-8").splitlines()
        check(len(source_lines) >= line and source_lines[line - 1] == rec.get("line_text"), f"{qid} source line mismatch")
        diag = finding_by_pos.get((path, line))
        check(diag is not None, f"{qid} lacks exact production CLI line match")
        if diag:
            check(diag.get("rule_id") == RULE and diag.get("source_sha256") == row["source_sha256"], f"{qid} CLI rule/source hash mismatch")
            check(rec.get("finding", {}).get("diagnostic_id") == diag.get("diagnostic_id"), f"{qid} CLI finding key mismatch")
        check(row["original_status"] == "not_testable" and row["queue_status"] == "paused_pending_evidence", f"{qid} unexpected frozen A0 state")
        check(rec.get("parse_status", {}).get("parse_status") in {"complete", "partial"}, f"{qid} missing parse status")

    # Every candidate source dispatcher must contain an exact token comparison before dispatch.
    macro_path = "services/utils/include/media_log.h"
    macro = git(args.git_dir, "show", f"{COMMIT}:{macro_path}").decode("utf-8")
    check("#define CHECK_AND_RETURN_RET_LOG(cond, ret, fmt, ...)" in macro and "if (!(cond))" in macro and "return ret;" in macro, "exact CHECK_AND_RETURN_RET_LOG early-return semantics not present")
    target_paths = sorted({r["path"] for r in target})
    for path in target_paths:
        text = git(args.git_dir, "show", f"{COMMIT}:{path}").decode("utf-8")
        lines = text.splitlines()
        qlines = [int(r["line"]) for r in target if r["path"] == path]
        start = max(0, min(qlines) - 170)
        end = max(qlines) + 1
        region = "\n".join(lines[start:end])
        check("ReadInterfaceToken()" in region, f"{path} does not read interface token near A0 lines")
        has_guard = "GetDescriptor() == remoteDescriptor" in region or (
            "data.ReadInterfaceToken() == PCMOutputCallbackStub::GetDescriptor()" in region
        )
        check(has_guard, f"{path} lacks Stub descriptor equality near A0 lines")
        check("CHECK_AND_RETURN_RET_LOG" in region, f"{path} does not guard descriptor with return macro near A0 lines")

    # Paired proxies, target build files and SA config are source-bound support evidence.
    proxy_by_stub = {
        "services/services/avmetadatahelper/ipc/helper_listener_stub.cpp": "services/services/avmetadatahelper/ipc/helper_listener_proxy.cpp",
        "services/services/lpp_audio_streamer/ipc/lpp_audio_streamer_listener_stub.cpp": "services/services/lpp_audio_streamer/ipc/lpp_audio_streamer_listener_proxy.cpp",
        "services/services/lpp_video_streamer/ipc/lpp_video_streamer_listener_stub.cpp": "services/services/lpp_video_streamer/ipc/lpp_video_streamer_listener_proxy.cpp",
        "services/services/media_source/ipc/media_source_loader_stub.cpp": "services/services/media_source/ipc/media_source_loader_proxy.cpp",
        "services/services/pcm_output/ipc/pcm_output_callback_stub.cpp": "services/services/pcm_output/ipc/pcm_output_callback_proxy.cpp",
        "services/services/player/ipc/player_listener_stub.cpp": "services/services/player/ipc/player_listener_proxy.cpp",
        "services/services/player/ipc/player_service_stub.cpp": "services/services/player/ipc/player_service_proxy.cpp",
        "services/services/recorder/ipc/recorder_service_stub.cpp": "services/services/recorder/ipc/recorder_service_proxy.cpp",
        "services/services/screen_capture_monitor/ipc/screen_capture_monitor_service_stub.cpp": "services/services/screen_capture_monitor/ipc/screen_capture_monitor_service_proxy.cpp",
        "services/services/transcoder/ipc/transcoder_listener_stub.cpp": "services/services/transcoder/ipc/transcoder_listener_proxy.cpp",
        "services/services/transcoder/ipc/transcoder_service_stub.cpp": "services/services/transcoder/ipc/transcoder_service_proxy.cpp",
    }
    for proxy in {proxy_by_stub[p] for p in target_paths}:
        src = git(args.git_dir, "show", f"{COMMIT}:{proxy}").decode("utf-8")
        check("WriteInterfaceToken(" in src, f"paired proxy lacks WriteInterfaceToken: {proxy}")
        check("SendRequest(" in src, f"paired proxy lacks SendRequest: {proxy}")
    support = audit.get("supporting_sources", {})
    for path, identity in support.items():
        try:
            raw = git(args.git_dir, "show", f"{COMMIT}:{path}")
            blob = git(args.git_dir, "rev-parse", f"{COMMIT}:{path}").decode().strip()
        except subprocess.CalledProcessError:
            errors.append(f"supporting source missing: {path}")
            continue
        check(blob == identity.get("blob") and hashlib.sha256(raw).hexdigest() == identity.get("sha256"), f"supporting source identity mismatch: {path}")
    check("services/services/BUILD.gn" in support and "interfaces/inner_api/native/BUILD.gn" in support and "services/etc/media_service.cfg" in support, "build/config source set incomplete")

    check(cli.get("status") == "completed_with_limitations", "unexpected production CLI status")
    check(cli.get("commit") == COMMIT and cli.get("git_tree") == TREE and cli.get("repository") == audit.get("repository"), "CLI source identity mismatch")
    check(cli.get("validated_vulnerability") == 0, "candidate replay must not claim confirmed vulnerabilities")
    check(audit.get("cli", {}).get("diagnostic_count") == len(findings) == 24, "expected 24 raw CLI findings")
    check(audit.get("cli", {}).get("a0_exact_position_hits") == 23, "expected 23 exact A0 line matches")
    check(len(audit.get("cli", {}).get("out_of_group_diagnostics", [])) == 1, "expected one explicitly uncounted extra candidate")
    check(cli.get("source_parsing", {}).get("parsing_status") == {"complete": 1, "partial": 10}, "parser result mismatch")
    check(audit.get("cli", {}).get("coverage", {}).get("status") == "partial", "IPC coverage must remain partial")
    check(hashlib.sha256(CLI.read_bytes()).hexdigest() == audit.get("cli", {}).get("json_sha256"), "raw CLI hash mismatch")
    check(audit.get("a0_original_status_counts") == {"not_testable": 23}, "A0 original status counts changed")
    check(audit.get("a0_queue_status_counts") == {"paused_pending_evidence": 23}, "A0 queue status counts changed")

    result = {
        "ok": not errors,
        "audit": "T42",
        "source_ids": len(target),
        "exact_cli_hits": sum((r["path"], int(r["line"])) in finding_by_pos for r in target),
        "raw_cli_findings": len(findings),
        "descriptor_guard_source_verified": not any("guard" in e or "macro" in e for e in errors),
        "proxy_transaction_source_verified": not any("paired proxy" in e for e in errors),
        "all_supporting_source_hashes_verified": not any("supporting source identity" in e for e in errors),
        "a0_status_preserved": not any("frozen A0 state" in e or "A0 original status" in e or "A0 queue status" in e for e in errors),
        "errors": errors,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
