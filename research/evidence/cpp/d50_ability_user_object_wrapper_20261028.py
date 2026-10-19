#!/usr/bin/env python3
"""Source-bound current shared_ptr_race replay for A0 CR-0314."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.cpp.shared_ptr_race_detector import SharedPtrRaceDetector
from src.ohscanner.fixture import snapshot_digest
from src.parser.ast import parse_source

COMMIT = "eaeaa31a6d07cf74fdec1c4e48dfe19c64e25cae"
TREE = "678c1c3a52e810919cc591b010cde7f97ff4d23c"
QUEUE_SNAPSHOT_SHA256 = "088feb3c9186b35dfc9dc3eb52732cd5bfe1df0786b83e63e529909111160886"
REPOSITORY = "openharmony/ability_ability_base"
TARGET = "interfaces/inner_api/base/include/user_object_wrapper.h"
TARGET_BLOB = "95ffabb86645db1109526e4a388f206d310a138e"
TARGET_SHA256 = "842a7ca8d07d419dff53521ab502cd5de8880c50052d48d9c8f1e679d47e91dc"
IMPL = "interfaces/inner_api/base/src/user_object_wrapper.cpp"
IMPL_BLOB = "716ea7ded87b8808ee5e4c03468e9b76e77a4bfc"
ROOT_BUILD = "BUILD.gn"
UNIT_BUILD = "test/unittest/BUILD.gn"
TEST = "test/unittest/base/user_object_wrapper_test.cpp"
PAC_MAP = "interfaces/kits/native/want/src/pac_map.cpp"


def git(repo: str, *args: str) -> bytes:
    return subprocess.check_output(["git", "--git-dir", repo, *args])


def get_source(repo: str, path: str) -> tuple[str, dict]:
    raw = git(repo, "show", f"{COMMIT}:{path}")
    return raw.decode("utf-8"), {
        "blob": git(repo, "rev-parse", f"{COMMIT}:{path}").decode().strip(),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source-git-dir", required=True)
    ap.add_argument("--output", type=Path)
    args = ap.parse_args()
    repo = str(Path(args.source_git_dir))
    assert git(repo, "rev-parse", f"{COMMIT}^{{tree}}").decode().strip() == TREE

    queue = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv"
    rows = {row["queue_id"]: row for row in csv.DictReader(queue.open(encoding="utf-8-sig", newline=""))}
    assert len(rows) == 345 and "CR-0314" in rows
    row = rows["CR-0314"]
    assert (row["repository"], row["commit"], row["tree"], row["path"], int(row["line"]),
            row["blob"], row["source_sha256"], row["original_status"], row["queue_status"]) == (
        REPOSITORY, COMMIT, TREE, TARGET, 25, TARGET_BLOB, TARGET_SHA256,
        "not_testable", "paused_pending_evidence")

    header, header_id = get_source(repo, TARGET)
    impl, impl_id = get_source(repo, IMPL)
    test, test_id = get_source(repo, TEST)
    root_build, root_build_id = get_source(repo, ROOT_BUILD)
    unit_build, unit_build_id = get_source(repo, UNIT_BUILD)
    pac_map, pac_map_id = get_source(repo, PAC_MAP)
    assert header_id["blob"] == TARGET_BLOB and header_id["sha256"] == TARGET_SHA256
    assert impl_id["blob"] == IMPL_BLOB

    index = parse_source(header, language="cpp")
    unit = SourceUnit(TARGET, "cpp", header, TARGET_SHA256, index.parse_status,
                      tuple(str(issue) for issue in index.parse_issues))
    units = (unit,)
    snapshot = snapshot_digest(units)
    req = ScanRequest("D50-CR0314-replay", REPOSITORY, COMMIT, snapshot,
                      f"current-component:{REPOSITORY}", "light-ast", "git_object")
    context = ScanContext(req, units, {"ast": {TARGET: index.to_dict()}})
    detector = SharedPtrRaceDetector()
    run = detector.detect(context, units)
    findings = [{"file": f.file, "line": f.line, "rule_id": f.rule_id,
                 "message": f.message} for f in run.findings]
    assert detector.version == "0.5.1" and unit.parse_status == "complete"
    assert run.status == "completed" and not findings

    # Source-level access/write accounting. The constructor is the sole initialization;
    # the implementation only reads value_ and returns shared_ptr copies.
    assert "UserObject(const std::shared_ptr<UserObjectBase> &value) : value_(value)" in header
    assert "std::shared_ptr<UserObjectBase> value_ = nullptr;" in header
    assert re.search(r"\bvalue_\s*=(?!=)", impl) is None
    assert impl.count("value_") >= 9
    assert "value = value_;" in impl
    assert "value_->" in impl and "otherObj->value_->" in impl
    assert '"interfaces/inner_api/base/src/user_object_wrapper.cpp"' in root_build
    assert 'ohos_shared_library("base")' in root_build
    assert "UserObject::" in test
    assert "user_object_wrapper_test.cpp" in unit_build
    assert "sptr<IUserObject> valObject = OHOS::AAFwk::UserObject::Box(value);" in pac_map
    put_object_start = pac_map.index("void PacMap::PutObject(")
    put_object_end = pac_map.index("void PacMap::InnerPutObject(", put_object_start)
    assert "std::lock_guard<std::mutex> mLock(mapLock_);" in pac_map[put_object_start:put_object_end]
    get_object_start = pac_map.index("std::shared_ptr<UserObjectBase> PacMap::GetObject(")
    get_object_end = pac_map.index("PacMap PacMap::GetPacMap(", get_object_start)
    get_object_body = pac_map[get_object_start:get_object_end]
    assert "std::lock_guard<std::mutex> mLock(mapLock_);" in get_object_body
    assert "return UserObject::Unbox(static_cast<IUserObject *>(it->second.GetRefPtr()));" in get_object_body

    result = {
        "schema_version": 1,
        "task": "D50",
        "review_id": "CR-0314",
        "original_a0_status": row["original_status"],
        "original_queue_status": row["queue_status"],
        "a0_status_mutated": False,
        "source": {
            "repository": REPOSITORY,
            "commit": COMMIT,
            "tree": TREE,
            "a0_snapshot_sha256": QUEUE_SNAPSHOT_SHA256,
            "target_file": TARGET,
            "target": header_id,
            "supporting_files": {
                IMPL: impl_id,
                TEST: test_id,
                ROOT_BUILD: root_build_id,
                UNIT_BUILD: unit_build_id,
                PAC_MAP: pac_map_id,
            },
        },
        "scanner": {
            "baseline_checkout": subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"]).decode().strip(),
            "detector_id": detector.detector_id,
            "detector_version": detector.version,
            "run_scope": [TARGET],
            "run_snapshot_sha256": snapshot,
            "parse_status": unit.parse_status,
            "parse_issues": list(index.parse_issues),
            "run_status": run.status,
            "findings": findings,
            "limitations": list(run.limitations),
            "analysis_coverage": "exact header detector replay; implementation/callsite/build context separately source-bound",
        },
        "source_review": {
            "field": "UserObject::value_",
            "write_sites": ["constructor initializer at user_object_wrapper.h:25 (initialization before normal publication)"] + (["field default initializer at user_object_wrapper.h:48"] if "std::shared_ptr<UserObjectBase> value_ = nullptr;" in header else []),
            "post_construction_assignment_in_implementation": False,
            "read_sites": ["GetValue copies value_ to caller output", "Equals reads value_ and otherObj->value_", "ToString reads value_"],
            "guard_or_atomic": "No lock/atomic is present around value_; source evidence does not establish a shared_ptr write after construction to race with these reads.",
            "component_call_context": "Pinned PacMap::PutObject and GetObject acquire mapLock_; PutObject constructs/stores the wrapper while locked, and GetObject calls Unbox/GetValue while locked. This covers these component call paths only; external IUserObject callers remain unbound.",
            "build": "The pinned root BUILD.gn includes user_object_wrapper.cpp in ohos_shared_library(\"base\"); exact product profile/image inclusion is not verified.",
            "tests": "Pinned test/unittest/BUILD.gn registers user_object_wrapper_test as an ohos_unittest; it does not establish concurrent product call paths.",
        },
        "assessment": {
            "finding_at_a0_location": any(f["file"] == TARGET and f["line"] == 25 for f in findings),
            "specific_detector_gap_proven": False,
            "classification": "no_change; source shows constructor-only holder initialization and read-only post-construction accesses; no actual unsynchronized same-member write/read pair was established",
            "result": "PARTIAL/BLOCK",
            "limitations": [
                "No trusted vulnerable/fixed pair or target-derived concurrent harness is bound.",
                "Product build/profile and downstream call/thread lifecycle are unknown.",
                "The wrapped UserObjectBase object's own mutability is outside the reported shared_ptr holder race and requires separate evidence.",
                "Static source evidence and a quiet detector result do not prove product safety.",
            ],
        },
        "a0_reconciliation": {"queue_rows": len(rows), "original_statuses_unchanged": True},
    }
    if args.output:
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("PASS D50: exact CR-0314 A0 commit/tree/blob/SHA and unchanged original queue row")
    print("PASS D50: current shared_ptr_race 0.5.1 replay; target header parse complete, no candidate")
    print("PASS D50: bound implementation/build/test source identities; no post-construction holder assignment")
    print(json.dumps({"detector": detector.detector_id, "version": detector.version,
                      "parse_status": unit.parse_status, "run_status": run.status,
                      "finding_count": len(findings), "findings": findings,
                      "source_target_sha256": header_id["sha256"],
                      "source_target_blob": header_id["blob"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
