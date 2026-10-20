#!/usr/bin/env python3
"""Verify T51 source identity, current IPC replay, and test-only classification."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
COMMIT = "e1e278bc85dc0277ab79cfdc029558a61492d3da"
TREE = "74f22f00256d82a81ad9c1965ae0ec64ce3936a1"
REPO = "openharmony/customization_enterprise_device_management"
SOURCE = "test/unittest/services/edm/src/system_timer_manager_test.cpp"
SOURCE_SHA256 = "e34724edb8dc221ee9b17eebc20a01acefade0f0414d79eda4d8944c2830bbc2"
SOURCE_BLOB = "ba005fd32dc4c38b1534166bec129a8e70952fdd"
QUEUE_JSON = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.json"
QUEUE_CSV = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv"
CLI_JSON = HERE / "t51_edm_cr0313_cli_20261028.json"
AUDIT_JSON = HERE / "t51_edm_cr0313_audit_20261028.json"
AUDIT_MD = HERE / "t51_edm_cr0313_audit_20261028.md"
QID = "CR-0313"


def git(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), *args])


def object_record(repo: Path, path: str) -> dict:
    data = git(repo, "show", f"{COMMIT}:{path}")
    oid = git(repo, "rev-parse", f"{COMMIT}:{path}").decode().strip()
    return {"path": path, "blob": oid, "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data), "text": data.decode("utf-8")}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source-repo", type=Path, required=True,
                    help="OpenHarmony project Git repo or project-objects bare repo")
    args = ap.parse_args()
    repo = args.source_repo.resolve()
    assert git(repo, "rev-parse", f"{COMMIT}^{{commit}}").decode().strip() == COMMIT
    assert git(repo, "rev-parse", f"{COMMIT}^{{tree}}").decode().strip() == TREE

    qjson = json.loads(QUEUE_JSON.read_text(encoding="utf-8"))["queue"]
    with QUEUE_CSV.open(encoding="utf-8-sig", newline="") as f:
        qcsv = list(csv.DictReader(f))
    assert len(qjson) == len(qcsv) == 345
    jrows = [r for r in qjson if r["queue_id"] == QID]
    crows = [r for r in qcsv if r["queue_id"] == QID]
    assert len(jrows) == len(crows) == 1
    row = jrows[0]
    for key in ("candidate_id", "repository", "commit", "tree", "path", "line", "blob",
                "source_sha256", "original_status", "queue_status"):
        assert str(row[key]) == str(crows[0][key]), key
    assert (row["repository"], row["commit"], row["tree"], row["path"], int(row["line"]),
            row["blob"], row["source_sha256"], row["original_status"], row["queue_status"]) == (
                REPO, COMMIT, TREE, SOURCE, 70, SOURCE_BLOB, SOURCE_SHA256,
                "not_testable", "paused_pending_evidence")

    src = object_record(repo, SOURCE)
    test_build = object_record(repo, "test/unittest/services/edm/BUILD.gn")
    prod_build = object_record(repo, "services/edm/BUILD.gn")
    assert (src["blob"], src["sha256"]) == (SOURCE_BLOB, SOURCE_SHA256)
    assert "class TestTimerCallbackStub : public IRemoteStub<ITimerCallback>" in src["text"]
    assert "int32_t OnRemoteRequest(uint32_t code, MessageParcel &data" in src["text"]
    assert 'ohos_unittest("EdmServicesUnitTest")' in test_build["text"]
    assert '"./src/system_timer_manager_test.cpp"' in test_build["text"]
    assert 'ohos_static_library("edmservice_static")' in test_build["text"]
    # The helper library is explicitly test-only, and the candidate test file is
    # part of the ohos_unittest target. The production shared library is separate.
    assert "ohos_static_library(\"edmservice_static\") {\n  testonly = true" in test_build["text"]
    assert 'ohos_shared_library("edmservice")' in prod_build["text"]
    assert '"./src/system_manager/system_timer_manager.cpp"' in prod_build["text"]
    assert "TestTimerCallbackStub" not in prod_build["text"]
    assert "TestTimerCallbackStub" not in git(repo, "show", f"{COMMIT}:services/edm/src/system_manager/system_timer_manager.cpp").decode()

    cli = json.loads(CLI_JSON.read_text(encoding="utf-8"))
    assert (cli["repository"], cli["commit"], cli["git_tree"], cli["profile_id"]) == (REPO, COMMIT, TREE, "light-ast")
    assert cli["scope"]["declared_scope"] == [SOURCE]
    assert cli["scope"]["selected_source_files"] == 1
    assert cli["source_parsing"]["parsing_status"] == {"partial": 1}
    run = cli["detector_runs"][0]
    assert (run["tool"], run["tool_version"], run["status"], run["diagnostic_count"]) == (
        "ohscanner.interface.ipc", "0.12.12", "completed", 0)
    coverage = cli["detector_coverage"]["detectors"]["ohscanner.interface.ipc"]
    assert coverage["status"] == "partial"
    assert coverage["partially_inspected_files"] == [SOURCE]
    assert coverage["unexamined"][0]["reason"] == "detector_model_incomplete"

    result = {
        "audit": "T51",
        "case": QID,
        "a0_binding": {k: row[k] for k in (
            "candidate_id", "repository", "commit", "tree", "path", "line", "blob",
            "source_sha256", "original_status", "queue_status", "detector", "detector_version", "rule")},
        "source_objects": {k: {kk: vv for kk, vv in obj.items() if kk != "text"}
                           for k, obj in (("candidate", src), ("test_build", test_build), ("product_build", prod_build))},
        "current_cli": {"profile_id": cli["profile_id"], "snapshot_sha256": cli["snapshot_sha256"],
                        "scope_files": cli["scope"]["selected_source_files"],
                        "scope_bytes": cli["scope"]["selected_source_bytes"],
                        "parser_status": cli["source_parsing"]["parsing_status"],
                        "detector": run["tool"], "detector_version": run["tool_version"],
                        "findings": run["diagnostic_count"], "coverage_status": coverage["status"],
                        "coverage_reason": coverage["unexamined"][0]["reason"]},
        "build_classification": {"test_target": "EdmServicesUnitTest (ohos_unittest)",
                                 "test_source_condition": "!enterprise_device_management_feature_pc_only",
                                 "test_support_library_testonly": True,
                                 "production_target": "edmservice (ohos_shared_library)",
                                 "production_timer_manager_source": "services/edm/src/system_manager/system_timer_manager.cpp",
                                 "candidate_stub_present_in_production": False},
        "source_semantics": {"candidate_symbol": "TestTimerCallbackStub::OnRemoteRequest",
                             "test_behavior": "The test callback consumes its local MessageParcel and dispatches a timer ID.",
                             "production_behavior": "SystemTimerManager::OnTimerTriggered sends a callback request to the client; the test stub is not that production entry."},
        "disposition": "PARTIAL/BLOCK",
        "interpretation": "The A0 line maps to a test-only callback stub, not a demonstrated product IPC flaw. Current CLI has zero findings but partial parser/model coverage, so this is not a safety result. Preserve original A0 status and paused queue state.",
        "queue_reconciliation": {"rows_json": len(qjson), "rows_csv": len(qcsv),
                                 "original_status": row["original_status"], "queue_status": row["queue_status"],
                                 "status_changed": False},
    }
    AUDIT_JSON.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    md = f'''# T51 — EDM CR-0313 source and scanner audit\n\n## Result\n\n**PARTIAL/BLOCK.** CR-0313 is bound to `{COMMIT}` / tree `{TREE}`, exact source blob `{SOURCE_BLOB}` and SHA-256 `{SOURCE_SHA256}`. It remains `not_testable / paused_pending_evidence`; A0 queue state is unchanged.\n\nThe candidate at `{SOURCE}:70` is `TestTimerCallbackStub::OnRemoteRequest`, a local test callback implementation. GN places the source in `EdmServicesUnitTest` (`ohos_unittest`) behind `!enterprise_device_management_feature_pc_only`; its helper library `edmservice_static` has `testonly = true`. The separate production `edmservice` shared library includes `services/edm/src/system_manager/system_timer_manager.cpp`. The candidate test stub does not appear in production source. This supports a **test-harness-only candidate** and does not establish a product vulnerability.\n\n## Current IPC replay\n\nThe current `light-ast` replay indexed one file ({cli['scope']['selected_source_bytes']} bytes), parser status `{json.dumps(cli['source_parsing']['parsing_status'])}`, and ran `{run['tool']} {run['tool_version']}`. It produced zero findings. IPC coverage is `partial` with reason `detector_model_incomplete`; therefore zero findings are not a safety conclusion, and the case remains blocked pending evidence for the original entry/trigger/impact obligations.\n\n## Reproducibility\n\n- Replay: `python research/evidence/cpp/t51_edm_cr0313_replay_20261028.py --source-repo <project-git-repo> --json-out research/evidence/cpp/t51_edm_cr0313_cli_20261028.json --md-out research/evidence/cpp/t51_edm_cr0313_cli_20261028.md`\n- Verify source/build bindings and all 345 queue rows: `python research/evidence/cpp/verify_t51_edm_cr0313_audit_20261028.py --source-repo <project-git-repo>`\n- Raw CLI output: `t51_edm_cr0313_cli_20261028.json`; machine audit: `t51_edm_cr0313_audit_20261028.json`.\n'''
    AUDIT_MD.write_text(md, encoding="utf-8")
    print(json.dumps({"overall_ok": True, "case": QID, "disposition": "PARTIAL/BLOCK",
                      "test_only_candidate": True, "findings": 0,
                      "parser": cli["source_parsing"]["parsing_status"],
                      "a0_rows": len(qjson), "queue_states_unchanged": True}, indent=2))


if __name__ == "__main__":
    main()
