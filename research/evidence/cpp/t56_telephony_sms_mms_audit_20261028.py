#!/usr/bin/env python3
"""T56 source-bound independent acceptance for telephony_sms_mms CR-0343–0345."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
REPORT = ROOT / "research/evidence/cpp/t56_telephony_sms_mms_audit_20261028.json"
QUEUE = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.json"
RECONCILIATION = ROOT / "research/deliveries/cpp/a0_triage_20261019/reconciliation_20261019.json"
EXPECTED_COMMIT = "41cef006c6c4b7fdc9ee0bb8d9ae659ee2ebbfd8"
EXPECTED_TREE = "c7815e6f0b9033ca71cf4edc119a2e5b8393b85a"
EXPECTED = {
    "services/sms/include/gsm/gsm_sms_cb_handler.h": ("8e207a69196444a873ac6e0dec96c4f2e873ab01", "05bf26f1501a56050e79bed0867528c6fb1411a150bb11307f4e77909efadeca"),
    "test/unittest/sms_delivery_callback_test.cpp": ("b1197c4e92af182977277f4198ae4b64695d4244", "a4a1962580f3acdcdbb77fba3f53180f1c0cc79e976209cc360ed3dafe487270"),
    "test/unittest/sms_send_callback_test.cpp": ("8d835581cb80564ffda030a85041320964013996", "d2e37e8b2b3b39242ba1f9ac46d74d9e01602ed5e2243d3de5244956b32c104c"),
}
SELECTED = {
    "CR-0343": ("ohscanner.cpp.shared_ptr_race:b23348aa59ff657d", "services/sms/include/gsm/gsm_sms_cb_handler.h", 39),
    "CR-0344": ("ohscanner.interface.ipc:9ec85d810df26dd0", "test/unittest/sms_delivery_callback_test.cpp", 31),
    "CR-0345": ("ohscanner.interface.ipc:4b84e7ca455a55fa", "test/unittest/sms_send_callback_test.cpp", 33),
}


def git(git_dir: str, *args: str) -> bytes:
    return subprocess.check_output(["git", f"--git-dir={git_dir}", *args], stderr=subprocess.PIPE)


def load(path: pathlib.Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--git-dir", required=True, help="telephony_sms_mms Git object database")
    parser.add_argument("--queue-json", type=pathlib.Path, default=QUEUE)
    args = parser.parse_args()
    report, queue, reconciliation = load(REPORT), load(args.queue_json), load(RECONCILIATION)
    errors: list[str] = []

    if report.get("source", {}).get("commit") != EXPECTED_COMMIT or report.get("source", {}).get("tree") != EXPECTED_TREE:
        errors.append("report source pin mismatch")
    if git(args.git_dir, "cat-file", "-t", EXPECTED_COMMIT).decode().strip() != "commit":
        errors.append("pinned source commit missing")
    if git(args.git_dir, "show", "-s", "--format=%T", EXPECTED_COMMIT).decode().strip() != EXPECTED_TREE:
        errors.append("pinned source tree mismatch")

    rows = {row.get("queue_id"): row for row in queue.get("queue", [])}
    if len(rows) != 345 or queue.get("queue_count") != 345:
        errors.append("A0 queue must retain 345 unique rows")
    for key, expected in {"not_reproduced": 9, "not_testable": 336}.items():
        actual = sum(row.get("original_status") == key for row in rows.values())
        if actual != expected:
            errors.append(f"A0 original {key} count changed: {actual}")
    if len(queue.get("queue", [])) != 345:
        errors.append("A0 queue has duplicate IDs")
    if not reconciliation.get("overall_ok") or reconciliation.get("source_candidates") != 345 \
            or reconciliation.get("unique_queue_ids") != 345:
        errors.append("canonical A0 reconciliation is not a clean 345-row result")
    if reconciliation.get("original_status_counts") != {"not_reproduced": 9, "not_testable": 336}:
        errors.append("canonical A0 original status counts mismatch")
    if reconciliation.get("queue_status_counts") != {
        "paused_pending_evidence": 331, "queued_first_batch": 5, "queued_not_reproduced": 9
    }:
        errors.append("canonical A0 queue status counts mismatch")

    for row_id, (candidate, path, line) in SELECTED.items():
        row = rows.get(row_id)
        if not row:
            errors.append(f"missing A0 row {row_id}")
            continue
        expected_row = {
            "candidate_id": candidate, "repository": "openharmony/telephony_sms_mms",
            "commit": EXPECTED_COMMIT, "tree": EXPECTED_TREE, "path": path, "line": line,
            "original_status": "not_testable", "queue_status": "paused_pending_evidence",
        }
        for key, value in expected_row.items():
            if row.get(key) != value:
                errors.append(f"{row_id} {key} mismatch: {row.get(key)!r} != {value!r}")

    source_map = {item["path"]: item for item in report.get("source_files", [])}
    expected_sources = {
        item["path"]: (item["blob"], item["sha256"])
        for item in report.get("source_files", [])
    }
    expected_sources.update(EXPECTED)
    for path, (expected_blob, expected_sha) in expected_sources.items():
        try:
            blob = git(args.git_dir, "rev-parse", f"{EXPECTED_COMMIT}:{path}").decode().strip()
            data = git(args.git_dir, "show", f"{EXPECTED_COMMIT}:{path}")
        except subprocess.CalledProcessError:
            errors.append(f"missing pinned source {path}")
            continue
        if blob != expected_blob or hashlib.sha256(data).hexdigest() != expected_sha:
            errors.append(f"pinned blob/SHA mismatch: {path}")
        item = source_map.get(path, {})
        if item.get("blob") != expected_blob or item.get("sha256") != expected_sha:
            errors.append(f"report source identity mismatch: {path}")

    replay_files = {
        "shared_ptr_header": ["services/sms/include/gsm/gsm_sms_cb_handler.h"],
        "ipc_test_callbacks": ["test/unittest/sms_delivery_callback_test.cpp", "test/unittest/sms_send_callback_test.cpp"],
        "shared_ptr_with_implementation_context": ["services/sms/include/gsm/gsm_sms_cb_handler.h", "services/sms/gsm/gsm_sms_cb_handler.cpp"],
    }
    for replay in report.get("cli_replays", []):
        raw = load(ROOT / replay["json"])
        key = replay["key"]
        if raw.get("commit") != EXPECTED_COMMIT or raw.get("git_tree") != EXPECTED_TREE:
            errors.append(f"{key}: CLI pin mismatch")
        if raw.get("status") != "completed" or raw.get("diagnostic_count") != 0:
            errors.append(f"{key}: unexpected CLI completion/findings")
        parsing = raw.get("source_parsing", {}).get("parsing_status", {})
        expected_count = len(replay_files[key])
        if parsing.get("complete") != expected_count or sum(parsing.values()) != expected_count:
            errors.append(f"{key}: parser coverage incomplete")
        runs = raw.get("detector_runs", [])
        if len(runs) != 1 or runs[0].get("tool") != replay["detector"] or runs[0].get("status") != "completed":
            errors.append(f"{key}: detector identity/status mismatch")
        elif runs[0].get("diagnostic_count") != 0:
            errors.append(f"{key}: detector emitted findings")
        selected_paths = set(raw.get("scope", {}).get("declared_scope", []))
        if selected_paths != set(replay_files[key]):
            errors.append(f"{key}: selected scope mismatch")
        expected_hashes = {
            path: source_map[path]["sha256"] for path in replay_files[key]
        }
        actual_hashes = raw.get("detector_coverage", {}).get("detectors", {}).get(
            replay["detector"], {}
        ).get("source_sha256", {})
        if actual_hashes != expected_hashes:
            errors.append(f"{key}: replay source SHA-256 mismatch")

    result = {
        "ok": not errors,
        "audit": "T56 telephony_sms_mms CR-0343–CR-0345",
        "disposition": "PARTIAL/BLOCK",
        "a0_rows": 345,
        "selected_original_states_preserved": not any("A0" in item or "original" in item for item in errors),
        "errors": errors,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
