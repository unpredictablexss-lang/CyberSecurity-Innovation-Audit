#!/usr/bin/env python3
"""Source-bound current IPC CLI replay for A0 CR-0306--CR-0312.

This verifier does not modify detector code or A0 statuses. It deliberately
excludes test-only CR-0313 from the production target replay.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
COMMIT = "e1e278bc85dc0277ab79cfdc029558a61492d3da"
TREE = "74f22f00256d82a81ad9c1965ae0ec64ce3936a1"
A0_CSV_SHA256 = "16d5702cfd60bc666ed8f041c48311546b190d32c9e66243b0e9dfa4e549caee"
A0_QUEUE = ROOT / "research" / "deliveries" / "cpp" / "a0_triage_20261019" / "queue.csv"
A0_QUEUE_SHA256 = "a174c0a74986e8410c53f173b84bb446c59000c3867add612a14e8aab4396d27"
A0_RECONCILIATION = ROOT / "research" / "deliveries" / "cpp" / "a0_triage_20261019" / "reconciliation_20261019.json"
TARGETS = [
    "services/edm/src/admin_manager.cpp",
    "services/edm/src/delay_unload_manager.cpp",
    "services/edm/src/enterprise_device_mgr_stub.cpp",
]
TEST_ONLY = "test/unittest/services/edm/src/system_timer_manager_test.cpp"
A0_CASES = {
    "CR-0306": (TARGETS[0], 240),
    "CR-0307": (TARGETS[1], 38),
    "CR-0308": (TARGETS[1], 42),
    "CR-0309": (TARGETS[2], 63),
    "CR-0310": (TARGETS[2], 75),
    "CR-0311": (TARGETS[2], 76),
    "CR-0312": (TARGETS[2], 90),
}
SUPPORT = [
    "services/edm/include/enterprise_device_mgr_stub.h",
    "services/edm/include/admin_manager.h",
    "services/edm/src/permission_checker.cpp",
    "services/edm/BUILD.gn",
    "common/config/common.gni",
    "test/unittest/services/edm/BUILD.gn",
    TEST_ONLY,
]
EXPECTED_FINDINGS = {
    ("services/edm/src/delay_unload_manager.cpp", 38),
    ("services/edm/src/delay_unload_manager.cpp", 42),
    ("services/edm/src/enterprise_device_mgr_stub.cpp", 75),
    ("services/edm/src/enterprise_device_mgr_stub.cpp", 76),
    ("services/edm/src/enterprise_device_mgr_stub.cpp", 90),
}


def run(*args: str, cwd: Path | None = None) -> str:
    return subprocess.check_output(args, cwd=cwd, text=True, encoding="utf-8").strip()


def git(repo: Path, *args: str) -> str:
    return run("git", "-C", str(repo), *args)


def source_identity(repo: Path, path: str) -> tuple[str, str, str]:
    raw = subprocess.check_output(
        ["git", "-C", str(repo), "show", f"{COMMIT}:{path}"]
    )
    blob = git(repo, "rev-parse", f"{COMMIT}:{path}")
    return blob, hashlib.sha256(raw).hexdigest(), raw.decode("utf-8")


def source_line(text: str, line: int) -> str:
    return text.splitlines()[line - 1]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source-repo", type=Path, required=True, help="local checkout with the pinned source commit")
    ap.add_argument("--a0-csv", type=Path, required=True, help="frozen original A0 candidate CSV")
    ap.add_argument("--a0-queue", type=Path, default=A0_QUEUE, help="frozen triage queue with source bindings and current queue states")
    ap.add_argument("--output", type=Path, required=True, help="D49 machine-readable report path")
    ap.add_argument("--cli-json", type=Path, required=True, help="raw current CLI JSON output path")
    ap.add_argument("--cli-md", type=Path, required=True, help="raw current CLI Markdown output path")
    args = ap.parse_args()
    source_repo = args.source_repo.resolve()
    a0_path = args.a0_csv.resolve()

    require(git(source_repo, "rev-parse", "HEAD") == COMMIT,
            "source checkout HEAD does not match pinned A0 source commit")
    require(git(source_repo, "rev-parse", f"{COMMIT}^{{tree}}") == TREE,
            "source Git tree does not match pinned A0 source tree")
    a0_digest = hashlib.sha256(a0_path.read_bytes()).hexdigest()
    require(a0_digest == A0_CSV_SHA256, f"A0 ledger hash mismatch: {a0_digest}")
    with a0_path.open("r", encoding="utf-8-sig", newline="") as f:
        rows = {row["review_id"]: row for row in csv.DictReader(f)}
    queue_path = args.a0_queue.resolve()
    queue_digest = hashlib.sha256(queue_path.read_bytes()).hexdigest()
    require(queue_digest == A0_QUEUE_SHA256, f"A0 triage queue hash mismatch: {queue_digest}")
    with queue_path.open("r", encoding="utf-8-sig", newline="") as f:
        queue_rows = {row["original_review_id"]: row for row in csv.DictReader(f)}
    reconciliation = json.loads(A0_RECONCILIATION.read_text(encoding="utf-8"))
    require(reconciliation["overall_ok"] is True and reconciliation["source_candidates"] == 345 and
            reconciliation["queue_rows"] == 345 and reconciliation["unique_queue_ids"] == 345,
            "full A0 triage reconciliation is not green")
    require(reconciliation["original_status_counts"] == {"not_reproduced": 9, "not_testable": 336} and
            reconciliation["queue_status_counts"] == {
                "paused_pending_evidence": 331, "queued_first_batch": 5, "queued_not_reproduced": 9
            }, "full A0 status/queue counts changed")
    selected = {}
    for case_id, (path, line) in A0_CASES.items():
        row = rows[case_id]
        queue_row = queue_rows[case_id]
        require(row["library"] == "customization_enterprise_device_management", f"{case_id}: library mismatch")
        require(row["scanner_provider"] == "ohscanner.interface.ipc", f"{case_id}: detector mismatch")
        require(row["rule_id"] == "ipc.relay.descriptor-boundary", f"{case_id}: rule mismatch")
        require(row["file"] == path and int(row["line"]) == line, f"{case_id}: source location mismatch")
        require(row["final_status"] == "not_testable", f"{case_id}: original A0 state changed")
        require(queue_row["commit"] == COMMIT and queue_row["tree"] == TREE,
                f"{case_id}: source commit/tree mismatch in triage queue")
        require(queue_row["path"] == path and int(queue_row["line"]) == line,
                f"{case_id}: source location mismatch in triage queue")
        require(queue_row["original_status"] == "not_testable" and
                queue_row["queue_status"] == "paused_pending_evidence",
                f"{case_id}: current triage status changed")
        blob, digest, _ = source_identity(source_repo, path)
        require(queue_row["blob"] == blob and queue_row["source_sha256"] == digest,
                f"{case_id}: queue-bound file identity mismatch")
        selected[case_id] = {"candidate_review": row, "triage_queue": queue_row}

    test_row = rows["CR-0313"]
    test_queue_row = queue_rows["CR-0313"]
    require(test_row["file"] == TEST_ONLY and test_row["final_status"] == "not_testable",
            "CR-0313 no longer matches its test-only A0 row")
    test_blob, test_digest, _ = source_identity(source_repo, TEST_ONLY)
    require(test_queue_row["commit"] == COMMIT and test_queue_row["tree"] == TREE and
            test_queue_row["path"] == TEST_ONLY and int(test_queue_row["line"]) == 70 and
            test_queue_row["blob"] == test_blob and test_queue_row["source_sha256"] == test_digest,
            "CR-0313 source binding changed")
    require(test_queue_row["original_status"] == "not_testable" and
            test_queue_row["queue_status"] == "paused_pending_evidence",
            "CR-0313 triage status changed")

    cli_json = args.cli_json.resolve()
    cli_md = args.cli_md.resolve()
    command = [
        sys.executable, "-m", "src.cli", "ohscan-run",
        "--repo-dir", str(source_repo),
        "--repository", "openharmony/customization_enterprise_device_management",
        "--commit", COMMIT,
    ]
    for path in TARGETS:
        command += ["--include", path]
    command += ["--detector", "ohscanner.interface.ipc", "--json-out", str(cli_json), "--md-out", str(cli_md)]
    run(*command, cwd=ROOT)
    raw_cli = json.loads(cli_json.read_text(encoding="utf-8"))
    require(raw_cli["status"] == "completed", "current IPC CLI run did not complete")
    require(raw_cli["commit"] == COMMIT and raw_cli["git_tree"] == TREE, "CLI source identity mismatch")
    require(raw_cli["scope"]["declared_scope"] == TARGETS, "CLI did not use exactly the three production target files")
    require(raw_cli["source_parsing"]["parsing_status"] == {"complete": 3}, "target parse coverage changed")
    det_runs = [d for d in raw_cli["detector_runs"] if d["tool"] == "ohscanner.interface.ipc"]
    require(len(det_runs) == 1, "expected exactly one IPC detector run")
    run_result = det_runs[0]
    finding_locations = {(d["file"], int(d["line"])) for d in run_result["diagnostics"]}
    require(finding_locations == EXPECTED_FINDINGS,
            f"current CLI finding locations changed: {sorted(finding_locations)}")
    require(run_result["tool_version"] == "0.12.12", "IPC detector version changed")

    texts: dict[str, str] = {}
    identities: dict[str, dict[str, str]] = {}
    for path in [*TARGETS, *SUPPORT]:
        blob, digest, text = source_identity(source_repo, path)
        texts[path] = text
        identities[path] = {"blob": blob, "sha256": digest}

    admin = texts[TARGETS[0]]
    delay = texts[TARGETS[1]]
    stub = texts[TARGETS[2]]
    stub_h = texts["services/edm/include/enterprise_device_mgr_stub.h"]
    checker = texts["services/edm/src/permission_checker.cpp"]
    build = texts["services/edm/BUILD.gn"]
    common_gni = texts["common/config/common.gni"]
    test_build = texts["test/unittest/services/edm/BUILD.gn"]
    test_source = texts[TEST_ONLY]

    require(source_line(admin, 240).strip() == "return AdminContainer::GetInstance()->IsAdminExist();",
            "CR-0306 source line no longer matches the bounded no-argument helper")
    require("void DelayUnloadManager::TryStartDelayUnload()" in delay and "AdminManager::GetInstance()->IsAdminExist()" in delay,
            "CR-0307 helper query source context changed")
    require("auto handler = GetEventHandler();" in delay and "handler->RemoveTask(DELAY_UNLOAD_TASK_NAME);" in delay,
            "CR-0308 does not resolve to the expected delayed-unload handler flow")
    require("EnterpriseDeviceMgrStub::OnRemoteRequestIdl" in stub, "IDL dispatcher definition missing")
    require("!PermissionChecker::GetInstance()->CheckIsSystemAppOrNative()" in stub,
            "CR-0309 system/native principal check missing")
    require("return EdmReturnErrCode::SYSTEM_API_DENIED;" in stub,
            "system/native check no longer denies before IDL dispatch")
    require("EnterpriseDeviceMgrIdlStub::OnRemoteRequest(code, data, reply, option)" in stub,
            "IDL dispatch target missing")
    require("class EnterpriseDeviceMgrStub : public EnterpriseDeviceMgrIdlStub, public IEnterpriseDeviceMgr" in stub_h,
            "Stub-to-IDL class binding missing")
    require("EnterpriseDeviceMgrStub::OnRemoteRequest(uint32_t code" in stub and
            "HandleOnRemoteRequest(code, data, reply, option)" in stub and
            "DelayUnloadManager::GetInstance()->TryStartDelayUnload();" in stub,
            "CR-0310/0311 ordering no longer shows post-handler unload check")
    require("if (SERVICE_FLAG(code))" in stub and "return OnRemoteRequestIdl(code, data, reply, option);" in stub,
            "CR-0312 IDL/service-flag branch changed")
    require("std::u16string remoteDescriptor = data.ReadInterfaceToken();" in stub and
            "if (descriptor != remoteDescriptor)" in stub and
            "return HandleNewInterfacePolicy(code, data, reply);" in stub,
            "non-IDL own-descriptor validation and dispatch changed")
    require("CheckIsSystemAppOrNative()" in checker and "CreateAccessTokenManager()->IsSystemAppOrNative()" in checker,
            "system/native source-backed permission helper changed")
    require('sources = [ "./src/enterprise_device_mgr_stub.cpp" ]' in build and
            '"./src/admin_manager.cpp"' in build and '"./src/delay_unload_manager.cpp"' in build,
            "production GN source declarations changed")
    require("if (enterprise_device_management_support_all)" in build and
            "enterprise_device_management_support_all = true" in common_gni,
            "component feature default / conditional production source context changed")
    require('"./src/system_timer_manager_test.cpp"' in test_build and
            "SystemTimerManagerTest" in test_source,
            "CR-0313 test-only build/source boundary changed")
    require(not any(path.startswith("test/") for path in raw_cli["scope"]["declared_scope"]),
            "test-only CR-0313 unexpectedly entered production replay scope")

    def identity(path: str) -> dict[str, str]:
        return identities[path]

    cases = []
    for case_id, (path, line) in A0_CASES.items():
        hit = (path, line) in finding_locations
        cases.append({
            "review_id": case_id,
            "path": path,
            "line": line,
            "original_a0_status": "not_testable",
            "current_cli_exact_line_finding": hit,
            "result": "candidate_reproduced" if hit else "not_reproduced_by_current_cli",
        })

    result = {
        "schema_version": 1,
        "task": "D49",
        "assessment": "no_change; no concrete detector gap reproduced",
        "result": "PARTIAL/BLOCK",
        "source": {
            "repository": "openharmony/customization_enterprise_device_management",
            "commit": COMMIT,
            "tree": TREE,
            "a0_candidate_csv": str(a0_path),
            "a0_candidate_csv_sha256": a0_digest,
            "a0_triage_queue": str(queue_path),
            "a0_triage_queue_sha256": queue_digest,
            "a0_reconciliation": {
                "overall_ok": reconciliation["overall_ok"],
                "source_candidates": reconciliation["source_candidates"],
                "queue_rows": reconciliation["queue_rows"],
                "unique_queue_ids": reconciliation["unique_queue_ids"],
                "original_status_counts": reconciliation["original_status_counts"],
                "queue_status_counts": reconciliation["queue_status_counts"],
                "failed_checks": [name for name, passed in reconciliation["checks"].items() if not passed],
            },
            "a0_rows": {case_id: selected[case_id] for case_id in selected},
            "production_targets": {path: identity(path) for path in TARGETS},
            "supporting_files": {path: identity(path) for path in SUPPORT},
            "test_only_excluded_case": {
                "review_id": "CR-0313",
                "path": TEST_ONLY,
                "line": 70,
                "original_a0_status": "not_testable",
                "identity": identity(TEST_ONLY),
                "a0_queue_row": test_queue_row,
                "test_build_identity": identity("test/unittest/services/edm/BUILD.gn"),
            },
        },
        "scanner": {
            "detector": run_result["tool"],
            "version": run_result["tool_version"],
            "model_version": "oh-ipc-2026.10-v32",
            "cli_status": raw_cli["status"],
            "profile_id": raw_cli["profile_id"],
            "scope": TARGETS,
            "parse_status": raw_cli["source_parsing"]["parsing_status"],
            "findings": [{"file": d["file"], "line": d["line"], "rule_id": d["rule_id"],
                          "diagnostic_id": d["diagnostic_id"]} for d in run_result["diagnostics"]],
            "limitation_notes": [
                "Complete syntax parsing covers the three selected target translation units only.",
                "IPC call/dispatch and permission reasoning is bounded; product profile, caller grants and runtime reachability remain unknown.",
                "The current CLI has no `ipc.relay.descriptor-boundary` line finding at A0 CR-0306 line 240 or CR-0309 line 63.",
            ],
        },
        "cases": cases,
        "source_review": {
            "CR-0306": "AdminManager::IsAdminExist() is a parameterless state query forwarding to AdminContainer; no parcel data is consumed at line 240. The dispatcher calls DelayUnloadManager after handler completion, so this helper is a post-dispatch side effect, not a descriptor relay sink.",
            "CR-0307_CR-0308": "TryStartDelayUnload checks whether an admin exists, then retrieves/removes/schedules an event-handler task. This does not consume the current request parcel or dispatch to another interface.",
            "CR-0309": "The system-code IDL branch checks CheckIsSystemAppOrNative and returns SYSTEM_API_DENIED before delegating to EnterpriseDeviceMgrIdlStub. Effective product token grants remain unverified.",
            "CR-0310_CR-0312": "OnRemoteRequest delegates to HandleOnRemoteRequest; SERVICE_FLAG routes to the IDL path. The other path reads the request interface token, compares it to the Stub's own descriptor, then dispatches. TryStartDelayUnload runs after the handler returns.",
            "build": "The EDM service GN target always includes the Stub and conditionally includes AdminManager/DelayUnloadManager when enterprise_device_management_support_all is enabled. The component common.gni default is true; reviewed product GN profile/image is unknown.",
            "CR-0313": "The row is under test/unittest and its source is listed in the unit-test BUILD.gn; it is excluded from the production CLI run.",
        },
        "decision": {
            "specific_detector_gap_proven": False,
            "rule_change": False,
            "public_api_schema_catalog_change": False,
            "a0_status_mutated": False,
            "original_status_preserved": {case_id: {"original_status": "not_testable",
                                                       "queue_status": "paused_pending_evidence"}
                                           for case_id in A0_CASES},
            "outstanding": [
                "No product GN profile or built image was bound.",
                "No external reachability, effective caller grant set or concrete security impact was established.",
                "No trusted fixed-source or product regression pair was supplied.",
                "A0 CR-0306 and CR-0309 locations are not reproduced by this exact current CLI replay; their original queue status remains unchanged.",
            ],
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("PASS D49: exact source commit/tree and A0 candidate ledger identity verified")
    print("PASS D49: all seven selected A0 queue IDs, source hashes and paused states reconcile")
    print("PASS D49: current production IPC CLI replayed three selected files; complete syntax parse 3/3; five candidates")
    print("PASS D49: CR-0306 and CR-0309 misses and post-dispatch/helper context checked; no specific detector gap proven")
    print("PASS D49: CR-0313 verified as test-only and excluded; all seven A0 statuses preserved")
    print(f"WROTE {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
