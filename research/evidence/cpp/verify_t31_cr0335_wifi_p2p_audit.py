#!/usr/bin/env python3
"""Verify T31's independent CR-0335 replay against frozen A0 identities."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).with_name("t31_cr0335_wifi_p2p_audit_20261021.json")
EXPECTED = {
    "wifi/frameworks/native/src/wifi_p2p_callback_stub.h": "8425637a6acea80dac4d67d9c1ebd41aa795724a",
    "wifi/frameworks/native/interfaces/wifi_manager_service_ipc_interface_code.h": "df9b8e086e551527f11d1d4432c6b50506fe765d",
}


def git(git_dir: str, *args: str) -> bytes:
    return subprocess.check_output(["git", f"--git-dir={git_dir}", *args], stderr=subprocess.PIPE)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--git-dir", required=True)
    parser.add_argument("--queue", required=True, type=Path)
    parser.add_argument("--cli-json", required=True, type=Path)
    args = parser.parse_args()
    audit = json.loads(AUDIT.read_text(encoding="utf-8"))
    queue = json.loads(args.queue.read_text(encoding="utf-8"))
    cli = json.loads(args.cli_json.read_text(encoding="utf-8"))
    errors: list[str] = []

    row = next((item for item in queue["queue"] if item["queue_id"] == "CR-0335"), None)
    if row is None:
        errors.append("CR-0335 missing from frozen queue")
    else:
        expected_row = {
            "candidate_id": audit["candidate_id_a0"],
            "commit": audit["commit"],
            "tree": audit["tree"],
            "blob": audit["candidate_source"]["blob"],
            "source_sha256": audit["candidate_source"]["sha256"],
            "original_status": audit["a0_status"]["original_status"],
            "queue_status": audit["a0_status"]["queue_status"],
        }
        for field, expected in expected_row.items():
            if row.get(field) != expected:
                errors.append(f"A0 {field} mismatch: {row.get(field)!r} != {expected!r}")

    commit, tree = audit["commit"], audit["tree"]
    if git(args.git_dir, "cat-file", "-t", commit).decode().strip() != "commit":
        errors.append("A0 commit object type is not commit")
    if git(args.git_dir, "show", "-s", "--format=%T", commit).decode().strip() != tree:
        errors.append("A0 commit root tree mismatch")
    if git(args.git_dir, "cat-file", "-t", tree).decode().strip() != "tree":
        errors.append("A0 tree object type mismatch")

    source = audit["candidate_source"]
    source_bytes = git(args.git_dir, "show", f"{commit}:{source['path']}")
    source_lines = source_bytes.decode("utf-8").splitlines()
    if git(args.git_dir, "rev-parse", f"{commit}:{source['path']}").decode().strip() != source["blob"]:
        errors.append("candidate path blob differs from frozen A0")
    if hashlib.sha256(source_bytes).hexdigest() != source["sha256"]:
        errors.append("candidate path bytes SHA-256 differs from frozen A0")
    n = source["candidate_line"]
    if len(source_lines) < n or source_lines[n - 1] != source["candidate_line_text"]:
        errors.append("candidate source line text mismatch")
    function = "\n".join(source_lines[source["reviewed_range"][0] - 1 : source["reviewed_range"][1]])
    for text in (
        "WifiP2pCallbackStub::RemoteOnConfigChanged",
        "if (cfgLen <= 0)",
        "if (cfgLen > MAX_LEN)",
        "data.ReadBuffer(cfgLen)",
        "new (std::nothrow) char[cfgLen]",
        "memcpy_s(cfgData, cfgLen, dataBuffer, cfgLen)",
    ):
        if text not in function:
            errors.append(f"guard/function evidence missing: {text}")
    for path, blob in EXPECTED.items():
        if git(args.git_dir, "rev-parse", f"{commit}:{path}").decode().strip() != blob:
            errors.append(f"related transaction source blob mismatch: {path}")

    if cli.get("status") != "completed" or cli.get("commit") != commit:
        errors.append("CLI run is not completed on the queue-bound commit")
    if cli.get("git_tree") != tree or cli.get("repository") != audit["repository"]:
        errors.append("CLI source repository/tree mismatch")
    if cli.get("profile_id") != "light-ast":
        errors.append("CLI profile mismatch")
    parse = cli.get("source_parsing", {}).get("parsing_status", {})
    if parse.get("complete") != 1 or sum(parse.values()) != 1:
        errors.append(f"target file not completely parsed: {parse}")
    coverage = cli.get("detector_coverage", {}).get("detectors", {}).get("ohscanner.interface.ipc", {})
    if coverage.get("status") != "complete" or coverage.get("source_sha256", {}).get(source["path"]) != source["sha256"]:
        errors.append("IPC target coverage/source hash mismatch")
    if cli.get("diagnostic_count") != 1:
        errors.append(f"expected one copy-range candidate, got {cli.get('diagnostic_count')}")
    runs = [r for r in cli.get("detector_runs", []) if r.get("tool") == "ohscanner.interface.ipc"]
    diagnostics = [d for run in runs for d in run.get("diagnostics", [])]
    expected_finding = audit["cli_replay"]["finding"]
    if len(diagnostics) != 1:
        errors.append("expected exactly one IPC diagnostic")
    else:
        d = diagnostics[0]
        for field in ("diagnostic_id", "rule_id", "file", "line", "symbol", "source_sha256"):
            if d.get(field) != expected_finding[field]:
                errors.append(f"CLI finding {field} mismatch: {d.get(field)!r}")

    result = {
        "ok": not errors,
        "record_id": "CR-0335",
        "source_identity_verified_against_frozen_a0": not any("A0 " in e or "candidate path" in e or "tree" in e for e in errors),
        "finding_key_and_line_verified": not any("finding" in e or "diagnostic" in e for e in errors),
        "source_guard_and_parse_coverage_verified": not any("guard" in e or "parse" in e or "coverage" in e for e in errors),
        "queue_state_preserved": row is not None and row.get("original_status") == "not_reproduced" and row.get("queue_status") == "queued_not_reproduced",
        "errors": errors,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
