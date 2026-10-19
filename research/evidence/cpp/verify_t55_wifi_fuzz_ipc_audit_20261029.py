#!/usr/bin/env python3
"""Verify T55's source identities, per-file IPC CLI replays, and A0 preservation."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[3]
REPORT = ROOT / "research/evidence/cpp/t55_wifi_fuzz_ipc_audit_20261029.json"
QUEUE = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.json"
EXPECTED_IDS = [f"CR-{n:04d}" for n in range(337, 341)]


def git(git_dir: str, *args: str) -> bytes:
    return subprocess.check_output(["git", f"--git-dir={git_dir}", *args], stderr=subprocess.PIPE)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--git-dir", required=True, help="communication_wifi object database")
    parser.add_argument("--queue-json", type=pathlib.Path, default=QUEUE)
    args = parser.parse_args()
    audit = json.loads(REPORT.read_text(encoding="utf-8"))
    queue = json.loads(args.queue_json.read_text(encoding="utf-8"))
    errors: list[str] = []
    commit, tree = audit["commit"], audit["tree"]
    if git(args.git_dir, "rev-parse", f"{commit}^{{tree}}").decode().strip() != tree:
        errors.append("pinned commit/tree mismatch")
    rows = {row["queue_id"]: row for row in queue.get("queue", [])}
    if len(queue.get("queue", [])) != 345 or len(rows) != 345:
        errors.append("A0 queue must remain 345 unique rows")
    a0_counts: dict[str, int] = {}
    for row in rows.values():
        a0_counts[row.get("original_status", "")] = a0_counts.get(row.get("original_status", ""), 0) + 1
    if a0_counts != {"not_testable": 336, "not_reproduced": 9}:
        errors.append(f"A0 original status counts changed: {a0_counts}")

    report_rows = audit.get("rows", [])
    if [r.get("a0_id") for r in report_rows] != EXPECTED_IDS:
        errors.append("T55 row IDs/order mismatch")
    for item in report_rows:
        row = rows.get(item["a0_id"])
        if row is None:
            errors.append(f"A0 row missing: {item['a0_id']}")
            continue
        expected = {"candidate_id": "candidate_id", "repository": "repository", "commit": "commit",
                    "tree": "tree", "path": "path", "line": "line", "blob": "blob",
                    "source_sha256": "source_sha256", "original_status": "original_status",
                    "queue_status": "queue_status"}
        for audit_key, queue_key in expected.items():
            if item.get(audit_key) != row.get(queue_key):
                errors.append(f"{item['a0_id']} {audit_key} differs from frozen A0")
        try:
            blob_oid = git(args.git_dir, "rev-parse", f"{commit}:{item['path']}").decode().strip()
            source = git(args.git_dir, "show", f"{commit}:{item['path']}")
        except subprocess.CalledProcessError:
            errors.append(f"missing source object: {item['path']}")
            continue
        if blob_oid != item["blob"] or hashlib.sha256(source).hexdigest() != item["source_sha256"]:
            errors.append(f"source blob/SHA mismatch: {item['a0_id']}")
        cli_info = item["current_cli"]
        cli_path = ROOT / "research/evidence/cpp" / cli_info["report_json"]
        md_path = ROOT / "research/evidence/cpp" / cli_info["report_markdown"]
        if not cli_path.is_file() or not md_path.is_file():
            errors.append(f"missing per-file CLI evidence: {item['a0_id']}")
            continue
        if hashlib.sha256(cli_path.read_bytes()).hexdigest() != cli_info["report_json_sha256"]:
            errors.append(f"CLI JSON digest mismatch: {item['a0_id']}")
        if hashlib.sha256(md_path.read_bytes()).hexdigest() != cli_info["report_markdown_sha256"]:
            errors.append(f"CLI Markdown digest mismatch: {item['a0_id']}")
        cli = json.loads(cli_path.read_text(encoding="utf-8"))
        runs = cli.get("detector_runs", [])
        if (cli.get("commit"), cli.get("git_tree"), cli.get("diagnostic_count"),
            cli.get("source_parsing", {}).get("parsing_status")) != (commit, tree, 0, {"complete": 1}):
            errors.append(f"per-file replay status/coverage mismatch: {item['a0_id']}")
        if len(runs) != 1 or (runs[0].get("tool"), runs[0].get("tool_version"),
            runs[0].get("status"), runs[0].get("diagnostic_count")) != (
            "ohscanner.interface.ipc", audit["current_detector_version"], "completed", 0):
            errors.append(f"per-file detector identity/count mismatch: {item['a0_id']}")

    if len(report_rows) != 4 or audit.get("result_summary") != {
        "rows": 4, "exact_source_bindings": 4, "individual_cli_runs": 4,
        "complete_parses": 4, "partial_parses": 0, "diagnostics": 0,
        "a0_statuses_changed": False,
    }:
        errors.append("summary does not reconcile with four independent rows")
    for item in audit.get("context_source_bindings", []):
        try:
            actual_oid = git(args.git_dir, "rev-parse", f"{commit}:{item['path']}").decode().strip()
            raw = git(args.git_dir, "show", f"{commit}:{item['path']}")
        except subprocess.CalledProcessError:
            errors.append(f"missing context source: {item['path']}")
            continue
        if actual_oid != item["blob"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            errors.append(f"context blob/SHA mismatch: {item['path']}")
    group = audit["gn_and_source_context"]["wifi_sta_fuzz_group"]
    if group.get("testonly") is not True or len(group.get("targets", [])) != 4:
        errors.append("GN fuzz group/testonly inventory mismatch")
    # Verify source-level harness/Stub/build claims against the pinned blobs.
    common = git(args.git_dir, "show", f"{commit}:wifi/test/fuzztest/wifi_sta/BUILD.gn").decode("utf-8")
    if "group(\"fuzztest\")" not in common or "testonly = true" not in common:
        errors.append("wifi_sta fuzz group is not visibly testonly")
    semantic = {
        "CR-0337": ("wifidevicestub_fuzzer", "WifiDeviceStubFuzzTest", "wifi_device_service_impl",
                    "std::shared_ptr<WifiDeviceStub> pWifiDeviceStub = std::make_shared<WifiDeviceServiceImpl>();",
                    "pWifiDeviceStub->OnRemoteRequest(code, data, reply, option);",
                    "wifi_device_ability", "wifi/services/wifi_standard/wifi_framework/wifi_manage/wifi_sta_sa/wifi_device_service_impl.h", "class WifiDeviceServiceImpl : public WifiDeviceStub {"),
        "CR-0338": ("wifihotspotstub_fuzzer", "WifiHotSpotStubFuzzTest", "wifi_hotspot_service_impl",
                    "std::shared_ptr<WifiHotspotStub> pWifiHotspotServiceImpl = std::make_shared<WifiHotspotServiceImpl>();",
                    "pWifiHotspotServiceImpl->OnRemoteRequest(code, data, reply, option);",
                    "wifi_hotspot_ability", "wifi/services/wifi_standard/wifi_framework/wifi_manage/wifi_ap_sa/wifi_hotspot_service_impl.h", "class WifiHotspotServiceImpl : public WifiHotspotStub {"),
        "CR-0339": ("wifip2pstub_fuzzer", "WifiP2pStubFuzzTest", "wifi_p2p_service_impl",
                    "sptr<WifiP2pStub> pWifiP2pServiceImpl = WifiP2pServiceImpl::GetInstance();",
                    "pWifiP2pServiceImpl->OnRemoteRequest(code, data, reply, option);",
                    "wifi_p2p_ability", "wifi/services/wifi_standard/wifi_framework/wifi_manage/wifi_p2p_sa/wifi_p2p_service_impl.h", "class WifiP2pServiceImpl : public SystemAbility, public WifiP2pStub {"),
        "CR-0340": ("wifiscanstub_fuzzer", "WifiScanStubFuzzTest", "wifi_scan_service_impl",
                    "std::shared_ptr<WifiScanStub> pWifiScanServiceImpl = std::make_shared<WifiScanServiceImpl>();",
                    "pWifiScanServiceImpl->OnRemoteRequest(code, data, reply, option);",
                    "wifi_scan_ability", "wifi/services/wifi_standard/wifi_framework/wifi_manage/wifi_scan_sa/wifi_scan_service_impl.h", "class WifiScanServiceImpl : public WifiScanStub {"),
    }
    for item in report_rows:
        folder, target, dep, ctor, invoke, ability, header_path, inherit = semantic[item["a0_id"]]
        harness_path = f"wifi/test/fuzztest/wifi_sta/{folder}/{folder}.cpp"
        harness = git(args.git_dir, "show", f"{commit}:{harness_path}").decode("utf-8")
        header = git(args.git_dir, "show", f"{commit}:{header_path}").decode("utf-8")
        build_path = f"wifi/test/fuzztest/wifi_sta/{folder}/BUILD.gn"
        build = git(args.git_dir, "show", f"{commit}:{build_path}").decode("utf-8")
        if ctor not in harness or invoke not in harness or inherit not in header:
            errors.append(f"{item['a0_id']} harness/production Stub source relation not found")
        if f'ohos_fuzztest(\"{target}\")' not in build or f'\"{folder}.cpp\"' not in build or f":{dep}" not in build:
            errors.append(f"{item['a0_id']} fuzz target/source/dependency binding missing")
        if f'\"{folder}:{target}\"' not in common:
            errors.append(f"{item['a0_id']} target missing from testonly fuzz group")
        prod = git(args.git_dir, "show", f"{commit}:wifi/services/wifi_standard/wifi_framework/wifi_manage/BUILD.gn").decode("utf-8")
        start = prod.find(f'ohos_shared_library(\"{ability}\")')
        end = prod.find('ohos_shared_library(\"', start + 1) if start >= 0 else -1
        segment = prod[start:end if end >= 0 else None] if start >= 0 else ""
        if "install_enable = true" not in segment or f":{dep}" not in segment:
            errors.append(f"{item['a0_id']} install-enabled production ability dependency not established")
    result = {"ok": not errors, "audit": "T55", "rows": EXPECTED_IDS,
              "disposition": "PARTIAL/BLOCK", "a0_rows_preserved": 345, "errors": errors}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
