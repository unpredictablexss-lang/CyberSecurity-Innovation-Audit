#!/usr/bin/env python3
"""Verify D47 exact A0 bindings, current scanner replay, and unchanged queue states."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
COMMIT = "35445b57d739a41cb916330935e61f1e83d982ca"
TREE = "2907d1748b46897c49c8f8c253c49384294a6a7a"
REPOSITORY = "openharmony/multimedia_camera_framework"
IDS = {f"CR-{number}" for number in ("0257", "0258", "0259", "0260")}
QUEUE = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv"
RAW = ROOT / "research/evidence/cpp/d47_camera_sharedptr_cli_20261027.json"
EXPECTED = {
    "CR-0257": ("common/utils/watch_dog.h", 34, "2b9eda5f6c23c895c033f1aa5514244e588ace74a3a5b81d8ffbeff43083c6ca", "3bc969ff348e39cc55387502ddfaf0b64d0ad1eb"),
    "CR-0258": ("frameworks/taihe/include/camera_auto_ref_taihe.h", 27, "d43b2035615f59cfd6307730ae8e247f6f89153597b954d1a02dc6b6b42005ba", "7696d21cf0dff92e54416f7f6131644c6d2e5a48"),
    "CR-0259": ("frameworks/taihe/include/camera_auto_ref_taihe.h", 43, "d43b2035615f59cfd6307730ae8e247f6f89153597b954d1a02dc6b6b42005ba", "7696d21cf0dff92e54416f7f6131644c6d2e5a48"),
    "CR-0260": ("frameworks/taihe/include/camera_auto_ref_taihe.h", 48, "d43b2035615f59cfd6307730ae8e247f6f89153597b954d1a02dc6b6b42005ba", "7696d21cf0dff92e54416f7f6131644c6d2e5a48"),
}


def git(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "--git-dir", str(repo), *args])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-repo", type=Path, required=True,
                        help="Pinned multimedia_camera_framework Git object store")
    args = parser.parse_args()
    source = args.source_repo.resolve()
    assert git(source, "rev-parse", f"{COMMIT}^{{commit}}").decode().strip() == COMMIT
    assert git(source, "rev-parse", f"{COMMIT}^{{tree}}").decode().strip() == TREE

    rows = {row["queue_id"]: row for row in csv.DictReader(QUEUE.open(encoding="utf-8-sig", newline=""))}
    assert len(rows) == 345 and IDS <= rows.keys()
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    assert raw["repository"] == REPOSITORY
    assert raw["commit"] == COMMIT and raw["git_tree"] == TREE
    assert raw["scope"]["declared_scope"] == sorted({record[0] for record in EXPECTED.values()})
    assert raw["source_parsing"]["parsing_status"] == {"complete": 2}
    run = raw["detector_runs"][0]
    assert (run["tool"], run["tool_version"], run["diagnostic_count"]) == (
        "ohscanner.cpp.shared_ptr_race", "0.5.1", 4
    )
    diagnostics = {(d["file"], int(d["line"])): d for d in run["diagnostics"]}

    statuses = {}
    for qid, (path, line, sha256, blob) in EXPECTED.items():
        row = rows[qid]
        assert row["repository"] == REPOSITORY and row["commit"] == COMMIT and row["tree"] == TREE
        assert row["path"] == path and int(row["line"]) == line
        assert row["source_sha256"] == sha256 and row["blob"] == blob
        content = git(source, "show", f"{COMMIT}:{path}")
        assert hashlib.sha256(content).hexdigest() == sha256
        assert git(source, "rev-parse", f"{COMMIT}:{path}").decode().strip() == blob
        assert row["original_status"] == "not_testable"
        assert row["queue_status"] == "paused_pending_evidence"
        statuses[qid] = row["queue_status"]

    taihe_build = git(source, "show", f"{COMMIT}:frameworks/taihe/BUILD.gn").decode("utf-8")
    listener_header = git(source, "show", f"{COMMIT}:frameworks/taihe/include/listener_base_taihe.h").decode("utf-8")
    listener_impl = git(source, "show", f"{COMMIT}:frameworks/taihe/src/listener_base_taihe.cpp").decode("utf-8")
    watchdog = git(source, "show", f"{COMMIT}:common/utils/watch_dog.h").decode("utf-8")
    assert 'taihe_shared_library("camera_taihe")' in taihe_build
    assert '"src/listener_base_taihe.cpp"' in taihe_build
    assert "std::mutex listMutex;" in listener_header
    assert "std::lock_guard<std::mutex> lock(callbackList.listMutex);" in listener_header
    assert "std::make_shared<Ani::Camera::AutoRef>(env_, callback, isOnce)" in listener_impl
    assert "callbackList.refList.erase(it);" in listener_impl and "callbackList.refList.clear();" in listener_impl
    assert watchdog.count("std::lock_guard<std::mutex> lock(mutex_);") == 3
    assert "Watchdog(const Watchdog& other) = delete;" in watchdog

    mapped = {qid: (path, line) in diagnostics for qid, (path, line, _, _) in EXPECTED.items()}
    assert mapped == {"CR-0257": False, "CR-0258": True, "CR-0259": True, "CR-0260": True}
    # The scanner's fourth result is the getter return at line 52, not an A0 row.
    assert ("frameworks/taihe/include/camera_auto_ref_taihe.h", 52) in diagnostics
    assert raw["detector_coverage"]["detectors"]["ohscanner.cpp.shared_ptr_race"]["status"] == "partial"
    assert statuses == {qid: "paused_pending_evidence" for qid in IDS}
    print("PASS D47 exact commit/tree/blob/SHA bindings for CR-0257–CR-0260")
    print("PASS D47 current shared_ptr_race 0.5.1 CLI: 2/2 parse complete, 4 findings")
    print("PASS D47 A0 location map: CR-0257 quiet; CR-0258–0260 matched; one extra getter finding")
    print("PASS D47 original A0 states unchanged; one candidate file remains partial")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
