#!/usr/bin/env python3
"""Verify T48 camera source bindings, production IPC CLI mapping, and A0 preservation."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
AUDIT = HERE / "t48_camera_callback_audit_20261027.json"
CLI = HERE / "t48_camera_cli_20261027.json"
COMMIT = "35445b57d739a41cb916330935e61f1e83d982ca"
TREE = "2907d1748b46897c49c8f8c253c49384294a6a7a"
EXPECTED = {f"CR-{i:04d}" for i in range(291, 300)}


def git(git_dir: str, *args: str) -> bytes:
    return subprocess.check_output(["git", f"--git-dir={git_dir}", *args], stderr=subprocess.PIPE)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--git-dir", required=True, help="full local OpenHarmony project object mirror")
    args = parser.parse_args()
    audit = json.loads(AUDIT.read_text(encoding="utf-8"))
    cli = json.loads(CLI.read_text(encoding="utf-8"))
    queue_path = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv"
    with queue_path.open(encoding="utf-8-sig", newline="") as stream:
        queue = list(csv.DictReader(stream))
    selected = {row["queue_id"]: row for row in queue if row["queue_id"] in EXPECTED}
    errors: list[str] = []

    def check(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    check(len(queue) == 345 and len({row["queue_id"] for row in queue}) == 345, "A0 queue must retain 345 unique rows")
    check(set(selected) == EXPECTED, "camera audit must bind CR-0291 through CR-0299 only")
    check(audit.get("a0_row_count") == 9 and len(audit.get("cases", [])) == 9, "audit case count mismatch")
    check(git(args.git_dir, "cat-file", "-t", COMMIT).decode().strip() == "commit", "source commit missing")
    check(git(args.git_dir, "show", "-s", "--format=%T", COMMIT).decode().strip() == TREE, "source tree mismatch")
    check(cli.get("commit") == COMMIT and cli.get("git_tree") == TREE, "CLI run is not pinned to A0 source object")
    check(cli.get("repository") == "openharmony/multimedia_camera_framework", "wrong CLI repository")
    check(cli.get("scope", {}).get("selected_source_files") == 4, "expected four scoped source files")
    check(cli.get("scope", {}).get("declared_scope") == audit["cli"]["scope"], "CLI scope mismatch")
    check(cli.get("environment", {}).get("build_profile") == "none", "expected explicit no-build-profile evidence")
    check(cli.get("status") == "completed_with_limitations", "CLI limitation status changed")
    run = next((item for item in cli.get("detector_runs", []) if item.get("tool") == "ohscanner.interface.ipc"), {})
    check(run.get("tool_version") == "0.12.12" and run.get("diagnostic_count") == 9, "IPC detector version/count mismatch")
    diagnostics = {(item.get("file"), int(item.get("line", -1)), item.get("rule_id")): item for item in run.get("diagnostics", [])}
    source_files = {item["path"]: item for item in audit["source_files"]}
    check(set(source_files) == set(cli["scope"]["declared_scope"]), "source identity scope differs from CLI")

    for path, source in source_files.items():
        check(git(args.git_dir, "rev-parse", f"{COMMIT}:{path}").decode().strip() == source["blob"], f"{path}: blob mismatch")
        raw = git(args.git_dir, "cat-file", "blob", source["blob"])
        check(hashlib.sha256(raw).hexdigest() == source["sha256"], f"{path}: SHA-256 mismatch")
        check(cli["detector_coverage"]["detectors"]["ohscanner.interface.ipc"]["source_sha256"].get(path) == source["sha256"], f"{path}: CLI source hash mismatch")

    for source in audit.get("supporting_files", []):
        path = source["path"]
        check(git(args.git_dir, "rev-parse", f"{COMMIT}:{path}").decode().strip() == source["blob"], f"support {path}: blob mismatch")
        raw = git(args.git_dir, "cat-file", "blob", source["blob"])
        check(hashlib.sha256(raw).hexdigest() == source["sha256"], f"support {path}: SHA-256 mismatch")

    def source_text(path: str) -> str:
        return git(args.git_dir, "show", f"{COMMIT}:{path}").decode("utf-8")

    callback_paths = sorted(path for path in source_files if "callback_stub" in path and path.endswith(".cpp"))
    check(len(callback_paths) == 3, "expected three callback Stub source files")
    for path in callback_paths:
        text = source_text(path)
        token_guard = "CHECK_RETURN_RET(data.ReadInterfaceToken() != GetDescriptor(), errCode);"
        check(token_guard in text, f"{path}: explicit token-vs-descriptor guard absent")
        check(text.index(token_guard) < text.index("switch (code)"), f"{path}: guard does not precede dispatch switch")
    photo_proxy = source_text("services/camera_service/binder/client/src/hstream_capture_photo_callback_proxy.cpp")
    thumb_proxy = source_text("services/camera_service/binder/client/src/hstream_capture_thumbnail_callback_proxy.cpp")
    check("data.WriteInterfaceToken(GetDescriptor());" in photo_proxy and "Remote()->SendRequest" in photo_proxy, "photo proxy token/send mapping missing")
    check("data.WriteInterfaceToken(GetDescriptor());" in thumb_proxy and "Remote()->SendRequest" in thumb_proxy, "thumbnail proxy token/send mapping missing")
    wm_client = source_text("services/camera_service/src/window_manager_utils/camera_window_manager_client.cpp")
    check("RegisterWindowManagerAgent(" in wm_client and "windowManagerAgent_" in wm_client, "window-manager callback registration context missing")
    svc_build = source_text("services/camera_service/BUILD.gn")
    check('ohos_shared_library("camera_service")' in svc_build and "install_enable = true" in svc_build and '"src/hcamera_service.cpp"' in svc_build, "camera_service GN target context mismatch")
    base_build = source_text("frameworks/native/camera/base/BUILD.gn")
    check('ohos_shared_library("camera_framework")' in base_build and "hstream_capture_photo_callback_stub.cpp" in base_build and "hstream_capture_thumbnail_callback_stub.cpp" in base_build, "camera_framework callback Stub GN inclusion missing")
    hcamera = source_text("services/camera_service/src/hcamera_service.cpp")
    check("CheckPermission(permissionName, callerToken)" in hcamera and "OHOS_PERMISSION_CAMERA" in hcamera and "IsInForeGround(callerToken)" in hcamera, "CreateCameraDevice permission/foreground source checks missing")
    check("OHOS_PERMISSION_CAMERA_SHARED" in hcamera, "separate CAMERA_SHARED privilege predicate missing")

    for case in audit["cases"]:
        qid = case["queue_id"]
        row = selected.get(qid)
        check(row is not None, f"{qid}: absent from A0")
        if row is None:
            continue
        for field in ("candidate_id", "repository", "commit", "tree", "path", "line", "blob", "source_sha256", "rule", "original_status", "queue_status"):
            check(str(row.get(field)) == str(case.get(field)), f"{qid}: {field} differs from frozen A0")
        check(row["original_status"] == "not_testable" and row["queue_status"] == "paused_pending_evidence", f"{qid}: frozen state changed")
        raw = git(args.git_dir, "cat-file", "blob", case["blob"])
        lines = raw.decode("utf-8").splitlines()
        check(len(lines) >= int(case["line"]) and lines[int(case["line"]) - 1] == case["line_text"], f"{qid}: exact line mismatch")
        finding = diagnostics.get((case["path"], int(case["line"]), case["rule"]))
        check(finding is not None, f"{qid}: production CLI line match absent")
        if finding:
            check(finding.get("rule_id") == case["rule"], f"{qid}: CLI rule mismatch")
            check(finding.get("source_sha256") == case["source_sha256"], f"{qid}: CLI source hash mismatch")
            check(finding.get("diagnostic_id") == case["finding_id"], f"{qid}: CLI finding key mismatch")

    check(audit.get("disposition") == "PARTIAL/BLOCK", "cases must remain PARTIAL/BLOCK")
    check(audit.get("cli", {}).get("complete_files") == 3 and audit.get("cli", {}).get("partial_files") == 1, "parse coverage classification mismatch")
    check(audit.get("cli", {}).get("build_profile") == "none", "build profile must remain unverified")
    check(audit.get("queue_preservation", {}).get("all_original_states_unchanged") is True, "A0 queue state preservation not recorded")
    check("CR-0300" not in selected, "CR-0300 is outside camera family and must not be included")
    if errors:
        print("\n".join(f"FAIL: {message}" for message in errors))
        return 1
    print("PASS T48: exact project commit/tree/blob/SHA and source lines verified for CR-0291–CR-0299")
    print("PASS T48: production IPC CLI 0.12.12 maps all nine frozen A0 positions")
    print("PASS T48: partial parser coverage, build profile none, and PARTIAL/BLOCK retained")
    print("PASS T48: A0 has 345 unique rows; original selected IDs/statuses preserved; CR-0300 excluded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
