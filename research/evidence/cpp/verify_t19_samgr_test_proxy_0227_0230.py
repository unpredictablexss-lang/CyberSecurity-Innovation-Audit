#!/usr/bin/env python3
"""Verify T19's exact Samgr source bindings, line mappings, and unchanged A0 states."""
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "research/evidence/cpp/a_t19_samgr_test_proxy_0227_0230_20261020.json"
QUEUE = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.json"
MIRROR = Path(r"D:\openHarmonyScanner\openharmony\.repo\project-objects\systemabilitymgr_samgr.git")
CASES = {
    "CR-0227": ("ohscanner.interface.ipc:50fb008ac115f39e", 74, "ipc.capability.export"),
    "CR-0228": ("ohscanner.interface.ipc:fdb22927fdab7ff9", 74, "ipc.relay.descriptor-boundary"),
    "CR-0229": ("ohscanner.interface.ipc:b8c3d84ba9882d10", 76, "ipc.capability.export"),
    "CR-0230": ("ohscanner.interface.ipc:8822234174213557", 76, "ipc.relay.descriptor-boundary"),
}


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(MIRROR), *args])


def main() -> None:
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    source = evidence["source"]
    commit, path = source["commit"], source["path"]
    assert git("rev-parse", commit + "^{tree}").decode().strip() == source["tree"]

    for item in [source, evidence["production_sources"]["proxy"], evidence["production_sources"]["receiver_stub"]]:
        target_path = item.get("path", path)
        entry = git("ls-tree", commit, target_path).decode().strip().split()
        assert len(entry) >= 3 and entry[2] == item["blob"], (target_path, entry)
        blob = git("cat-file", "blob", item["blob"])
        assert len(blob) == item["bytes"], target_path
        assert hashlib.sha256(blob).hexdigest() == item["sha256"], target_path

    source_text = git("cat-file", "blob", source["blob"]).decode("utf-8").splitlines()
    assert "return reply.WriteRemoteObject(remoteObject_) ? ERR_NONE : ERR_FLATTEN_OBJECT;" in source_text[73]
    assert "return reply.WriteRemoteObject(remoteObject_) &&" in source_text[75]
    assert "(!writeExist_ || reply.WriteBool(true))" in "\n".join(source_text[75:77])
    assert "class MultiUserProxyRemoteStub" in "\n".join(source_text[45:95])
    assert "#ifdef SUPPORT_MULTI_INSTANCE" in "\n".join(source_text[40:48])
    proxy = git("cat-file", "blob", evidence["production_sources"]["proxy"]["blob"]).decode("utf-8")
    stub = git("cat-file", "blob", evidence["production_sources"]["receiver_stub"]["blob"]).decode("utf-8")
    for name in ("GetSystemAbility", "CheckSystemAbility", "CheckSystemAbilityByUserId", "GetLocalAbilityManagerProxy"):
        assert f"SystemAbilityManagerProxy::{name}" in proxy, name
    for name in ("GetSystemAbilityWithUserIdInner", "CheckSystemAbilityWithUserIdInner", "CheckSystemAbilityByUserIdInner", "GetLocalAbilityManagerProxyWithUserIdInner"):
        assert f"SystemAbilityManagerStub::{name}" in stub, name

    queue = json.loads(QUEUE.read_text(encoding="utf-8"))
    rows = {row["queue_id"]: row for row in queue["queue"] if row.get("queue_id") in CASES}
    report_rows = {row["queue_id"]: row for row in evidence["cases"]}
    assert set(rows) == set(CASES) and set(report_rows) == set(CASES)
    for queue_id, (candidate, line, rule) in CASES.items():
        row, review = rows[queue_id], report_rows[queue_id]
        assert row["candidate_id"] == candidate and row["line"] == line and row["rule"] == rule
        assert review["candidate_id"] == candidate and review["reported_line"] == line and review["rule"] == rule
        assert row["commit"] == commit and row["tree"] == source["tree"]
        assert row["blob"] == source["blob"] and row["source_sha256"] == source["sha256"]
        assert row["original_status"] == review["original_status"] == "not_testable"
        assert row["queue_status"] == review["queue_status"] == "paused_pending_evidence"
        assert row["source_file_analysis_status"] == "partial"
        assert review["product_flaw_conclusion"] == "not established"
    assert evidence["family_scope"]["queue_state"] == "all rows preserve original_status=not_testable and queue_status=paused_pending_evidence"
    print(json.dumps({"overall_ok": True, "ids": sorted(CASES), "commit": commit, "tree": source["tree"], "test_blob": source["blob"], "test_sha256": source["sha256"], "queue_states_preserved": True, "test_only_classification": True}, indent=2))


if __name__ == "__main__":
    main()
