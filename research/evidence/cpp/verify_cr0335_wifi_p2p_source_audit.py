#!/usr/bin/env python3
"""Verify CR-0335 source identities and line bindings against a Git object DB."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
EVIDENCE = pathlib.Path(__file__).with_name("cr0335_wifi_p2p_source_audit_20261020.json")
EXPECTED = {
    "candidate_source": "wifi/frameworks/native/src/wifi_p2p_callback_stub.cpp",
    "wifi/frameworks/native/src/wifi_p2p_callback_stub.h": "8425637a6acea80dac4d67d9c1ebd41aa795724a",
    "wifi/frameworks/native/interfaces/wifi_manager_service_ipc_interface_code.h": "df9b8e086e551527f11d1d4432c6b50506fe765d",
    "wifi/test/fuzztest/frameworks/native/c_adapter/wifip2pcbkstub_fuzzer/wifip2pcbkstub_fuzzer.cpp": "de9192ad7967d565a4f18d6c67e25cda9301c6ee",
    "wifi/test/fuzztest/frameworks/native/c_adapter/wifip2pcbkstub_fuzzer/BUILD.gn": "03956d31a5e746e56ff32165d7f7456fe2db8c46",
}


def run(git_dir: str, *args: str) -> bytes:
    return subprocess.check_output(["git", f"--git-dir={git_dir}", *args], stderr=subprocess.PIPE)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--git-dir", required=True, help="Git project object DB for communication_wifi")
    parser.add_argument("--queue", required=True, type=pathlib.Path, help="Frozen A0 queue.json")
    args = parser.parse_args()
    doc = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    queue = json.loads(args.queue.read_text(encoding="utf-8"))
    record = next((row for row in queue["queue"] if row["queue_id"] == "CR-0335"), None)
    errors: list[str] = []
    if record is None:
        errors.append("CR-0335 missing from the 345-row queue")
    else:
        queue_expected = {
            "candidate_id": doc["candidate_id"],
            "original_status": doc["original_status"],
            "queue_status": doc["queue_status"],
            "commit": doc["commit"],
            "tree": doc["tree"],
            "blob": doc["candidate_source"]["blob"],
            "source_sha256": doc["candidate_source"]["sha256"],
        }
        for field, expected in queue_expected.items():
            if record.get(field) != expected:
                errors.append(f"queue {field} mismatch: {record.get(field)!r} != {expected!r}")

    commit = doc["commit"]
    tree = doc["tree"]
    if run(args.git_dir, "cat-file", "-t", commit).decode().strip() != "commit":
        errors.append("commit object type mismatch")
    if run(args.git_dir, "show", "-s", "--format=%T", commit).decode().strip() != tree:
        errors.append("commit root tree mismatch")
    src = doc["candidate_source"]
    paths = {src["path"]: src["blob"]}
    for row in doc["related_files"]:
        paths[row["path"]] = row["blob"]
    for path, expected_blob in paths.items():
        actual_blob = run(args.git_dir, "rev-parse", f"{commit}:{path}").decode().strip()
        data = run(args.git_dir, "show", f"{commit}:{path}")
        if actual_blob != expected_blob:
            errors.append(f"blob mismatch for {path}: {actual_blob}")
        expected_sha = src["sha256"] if path == src["path"] else next(r["sha256"] for r in doc["related_files"] if r["path"] == path)
        if hashlib.sha256(data).hexdigest() != expected_sha:
            errors.append(f"SHA-256 mismatch for {path}")
    source_lines = run(args.git_dir, "show", f"{commit}:{src['path']}").decode("utf-8").splitlines()
    line_no = src["candidate_line"]
    if len(source_lines) < line_no or source_lines[line_no - 1] != src["candidate_line_text"]:
        errors.append("candidate line text mismatch")
    function_lines = "\n".join(source_lines[358:394])
    if "RemoteOnConfigChanged" not in function_lines:
        errors.append("candidate range is not bound to RemoteOnConfigChanged")
    for required in (
        "if (cfgLen <= 0)",
        "if (cfgLen > MAX_LEN)",
        "data.ReadBuffer(cfgLen)",
        "new (std::nothrow) char[cfgLen]",
        "memcpy_s(cfgData, cfgLen, dataBuffer, cfgLen)",
    ):
        if required not in function_lines:
            errors.append(f"copy-range guard/size relation missing: {required}")
    transaction = doc["transaction"]
    tx = run(args.git_dir, "show", f"{commit}:{transaction['registration_file']}").decode("utf-8").splitlines()
    if transaction["symbol"].split("::")[-1] not in tx[transaction["registration_line"] - 1]:
        errors.append("transaction constant line mismatch")
    fuzz_row = next(row for row in doc["related_files"] if row["path"].endswith("wifip2pcbkstub_fuzzer.cpp"))
    fuzz = run(args.git_dir, "show", f"{commit}:{fuzz_row['path']}").decode("utf-8")
    if "OnRemoteRequest(code, datas, reply, option)" not in fuzz:
        errors.append("fuzzer-to-stub call binding missing")
    alt_blob = "6106eb782ab6ffb605ec6ebff9e47ed5df923375"
    alt_type = run(args.git_dir, "cat-file", "-t", alt_blob).decode().strip()
    if alt_type != "blob":
        errors.append("message-provided alternative object missing or not a blob")
    alt_bytes = run(args.git_dir, "cat-file", "blob", alt_blob)
    alt_sha = hashlib.sha256(alt_bytes).hexdigest()
    if alt_sha != doc["identity_conflict"]["task_message_values"]["source_sha256"]:
        errors.append(f"message-provided SHA does not match alternate blob bytes: {alt_sha}")
    if alt_sha == src["sha256"]:
        errors.append("identity conflict unexpectedly disappeared; update the conflict note")
    if run(args.git_dir, "cat-file", "-t", tree).decode().strip() != "tree":
        errors.append("queue tree object type mismatch")
    for path, expected_blob in EXPECTED.items():
        if path == "candidate_source":
            continue
        if paths.get(path) != expected_blob:
            errors.append(f"hardcoded related identity mismatch for {path}")

    result = {
        "ok": not errors,
        "record_id": doc["record_id"],
        "candidate_id": doc["candidate_id"],
        "original_status": doc["original_status"],
        "queue_status": doc["queue_status"],
        "commit_tree_blob_sha_verified": not errors,
        "candidate_line_verified": not errors,
        "task_message_identity_conflict_preserved": True,
        "errors": errors,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
