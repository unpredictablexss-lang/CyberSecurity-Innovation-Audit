#!/usr/bin/env python3
"""Independent source-bound production CLI replay for A0 CR-0301–CR-0305."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from src.parser.ast import parse_source
from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.cpp.shared_ptr_race_detector import SharedPtrRaceDetector
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector
from src.ohscanner.fixture import snapshot_digest

COMMIT = "19188608475123695def986a399641bfa64a49f7"
TREE = "0ec80bfd6532b91f450d2f84517c461a4f7a18ae"
QUEUE = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv"
QUEUE_SNAPSHOT = "a2499e0c8f9ba4ec53e169f6c88d46cc10004f69d6b1b7339f80cf9b5891a4d5"

CASES = {
    "CR-0301": {
        "candidate": "ohscanner.cpp.shared_ptr_race:fbadd6da21877e43",
        "path": "services/intell_voice_engine/server/base/adapter_callback_service.h",
        "line": 28,
        "blob": "6ea96592785c7e8a80a6c737cfa660f90d00abe2",
        "sha256": "c849a94b117c762a10019817cd6899224c96f5eae3e7bbb0d76b7236f6680d7a",
        "detector": "shared_ptr",
        "expected_finding": False,
    },
    "CR-0302": {
        "candidate": "ohscanner.cpp.shared_ptr_race:92834dd99dd089bf",
        "path": "services/intell_voice_engine/server/base/engine_util.h",
        "line": 77,
        "blob": "372c98882e16df8f2e87e4b73936871cfb16b315",
        "sha256": "db1c9317dd3d170334ed98b4cbe2de93c34ab5dab328d684cab6babcfab0f3eb",
        "detector": "shared_ptr",
        "expected_finding": True,
    },
    "CR-0303": {
        "candidate": "ohscanner.cpp.shared_ptr_race:17827af15edb5483",
        "path": "services/intell_voice_engine/server/base/engine_util.h",
        "line": 78,
        "blob": "372c98882e16df8f2e87e4b73936871cfb16b315",
        "sha256": "db1c9317dd3d170334ed98b4cbe2de93c34ab5dab328d684cab6babcfab0f3eb",
        "detector": "shared_ptr",
        "expected_finding": True,
    },
    "CR-0304": {
        "candidate": "ohscanner.cpp.shared_ptr_race:984ccba14bff9bda",
        "path": "services/intell_voice_engine/server/base/engine_util.h",
        "line": 86,
        "blob": "372c98882e16df8f2e87e4b73936871cfb16b315",
        "sha256": "db1c9317dd3d170334ed98b4cbe2de93c34ab5dab328d684cab6babcfab0f3eb",
        "detector": "shared_ptr",
        "expected_finding": True,
    },
    "CR-0305": {
        "candidate": "ohscanner.interface.ipc:e777b1353fbbe284",
        "path": "services/intell_voice_service/server/sa/intell_voice_service_stub.cpp",
        "line": 70,
        "blob": "79a9acae7a4bb5a6dab18b40159f2aab52fcb544",
        "sha256": "55dc2d68954cf94eb41014010fc6696236d9839fa8246aebd2faa8d033d30fc6",
        "detector": "ipc",
        "expected_finding": True,
    },
}

SUPPORT = (
    "services/intell_voice_engine/server/base/adapter_callback_service.cpp",
    "services/intell_voice_engine/server/base/engine_util.cpp",
    "services/intell_voice_engine/server/enroll/enroll_engine.cpp",
    "services/intell_voice_engine/server/wakeup/headset/headset_wakeup_engine_impl.cpp",
    "services/intell_voice_engine/server/wakeup/high_power/high_power_wakeup_engine.cpp",
    "services/intell_voice_engine/server/wakeup/wakeup_engine_impl.cpp",
    "services/intell_voice_engine/BUILD.gn",
    "intell_voice_service.gni",
    "services/intell_voice_service/server/sa/intell_voice_service_stub.h",
    "services/intell_voice_service/server/sa/intell_voice_service.cpp",
    "services/intell_voice_service/server/sa/intell_voice_service.h",
    "services/intell_voice_engine/proxy/intell_voice_service_proxy.cpp",
)


def git(repo: str, *args: str) -> bytes:
    return subprocess.check_output(["git", "--git-dir", repo, *args])


def source(repo: str, path: str) -> tuple[str, dict]:
    raw = git(repo, "show", f"{COMMIT}:{path}")
    return raw.decode("utf-8"), {
        "blob": git(repo, "rev-parse", f"{COMMIT}:{path}").decode().strip(),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
    }


def scan(repo: str, review_id: str, case: dict) -> dict:
    text, identity = source(repo, case["path"])
    if (identity["blob"], identity["sha256"]) != (case["blob"], case["sha256"]):
        raise AssertionError(f"source identity mismatch for {review_id}: {identity}")
    tree = parse_source(text, language="cpp")
    unit = SourceUnit(case["path"], "cpp", text, identity["sha256"], tree.parse_status,
                      tuple(str(issue) for issue in tree.parse_issues))
    units = (unit,)
    snapshot = snapshot_digest(units)
    request = ScanRequest(
        f"T50-{review_id}-independent-replay", "openharmony/ai_intelligent_voice_framework",
        COMMIT, snapshot, "current-component:openharmony/ai_intelligent_voice_framework",
        "light-ast", "git_object",
    )
    context = ScanContext(request, units, {"ast": {case["path"]: tree.to_dict()}})
    detector = SharedPtrRaceDetector() if case["detector"] == "shared_ptr" else IpcInterfaceDetector()
    run = detector.detect(context, units)
    expected_rule = "ohcpp-shared-ptr-race-candidate-001" if case["detector"] == "shared_ptr" else "ipc.capability.export"
    position_matches = [f for f in run.findings if f.file == case["path"] and f.line == case["line"] and f.rule_id == expected_rule]
    if bool(position_matches) != case["expected_finding"]:
        raise AssertionError(f"unexpected candidate replay for {review_id}: {[(f.line, f.rule_id) for f in run.findings]}")
    return {
        "review_id": review_id,
        "candidate_id": case["candidate"],
        "target_file": case["path"],
        "a0_line": case["line"],
        "target_identity": identity,
        "run_snapshot_sha256": snapshot,
        "parse_status": unit.parse_status,
        "parse_issues": list(tree.parse_issues),
        "run_status": run.status,
        "detector_id": detector.detector_id,
        "detector_version": detector.version,
        "model_version": getattr(detector, "model_version", None),
        "findings": [{"file": f.file, "line": f.line, "rule_id": f.rule_id,
                      "message": f.message} for f in run.findings],
        "a0_root_candidate_reproduced": bool(position_matches),
        "limitations": list(run.limitations),
        "classification": "PARTIAL/BLOCK",
    }


def verify_a0_rows() -> list[dict]:
    with QUEUE.open(encoding="utf-8-sig", newline="") as stream:
        rows = {row["queue_id"]: row for row in csv.DictReader(stream)}
    if len(rows) != 345:
        raise AssertionError(f"A0 queue row count changed: {len(rows)}")
    result = []
    for review_id, case in CASES.items():
        row = rows.get(review_id)
        if not row:
            raise AssertionError(f"missing A0 row {review_id}")
        expected = (case["candidate"], case["path"], str(case["line"]), case["blob"], case["sha256"])
        actual = (row["candidate_id"], row["path"], row["line"], row["blob"], row["source_sha256"])
        if expected != actual:
            raise AssertionError(f"A0 identity mismatch {review_id}: {actual}")
        if row["original_status"] != "not_testable" or row["queue_status"] != "paused_pending_evidence":
            raise AssertionError(f"A0 status changed for {review_id}")
        result.append({"review_id": review_id, "candidate_id": row["candidate_id"],
                       "original_status": row["original_status"], "queue_status": row["queue_status"],
                       "source_sha256": row["source_sha256"], "mutated": False})
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-git-dir", required=True, help="bare object directory for the pinned component repository")
    parser.add_argument("--output", type=Path, help="optional JSON output path")
    args = parser.parse_args()
    repo = str(Path(args.source_git_dir))
    if git(repo, "rev-parse", f"{COMMIT}^{{tree}}").decode().strip() != TREE:
        raise AssertionError("component tree mismatch")

    a0 = verify_a0_rows()
    source_files = {}
    source_text = {}
    for path in SUPPORT:
        text, identity = source(repo, path)
        source_files[path] = identity
        source_text[path] = text
    evidence_json = ROOT / "research/evidence/cpp/t50_ai_voice_cr0301_cr0305_independent_20261028.json"
    if evidence_json.exists():
        prior = json.loads(evidence_json.read_text(encoding="utf-8"))
        if prior.get("source", {}).get("supporting_files") != source_files:
            raise AssertionError("supporting source identities differ from the T50 evidence JSON")
    callback_h = source(repo, CASES["CR-0301"]["path"])[0]
    engine_h = source(repo, CASES["CR-0302"]["path"])[0]
    callback_cpp = source_text["services/intell_voice_engine/server/base/adapter_callback_service.cpp"]
    engine_cpp = source_text["services/intell_voice_engine/server/base/engine_util.cpp"]
    build = source_text["services/intell_voice_engine/BUILD.gn"]
    gni = source_text["intell_voice_service.gni"]
    assert "listener_(listener)" in callback_h and "listener_->OnIntellVoiceHdiEvent(event)" in callback_cpp
    assert "std::shared_ptr<IAdapterHostManager> adapter_" in engine_h
    assert "adapter_ = mgr.CreateEngineAdapter(desc_);" in engine_h and "adapter_ = nullptr;" in engine_h
    engine_class_start = engine_h.index("class EngineUtil {")
    engine_class_end = engine_h.index("};", engine_class_start)
    engine_class = engine_h[engine_class_start:engine_class_end]
    assert "std::mutex " not in engine_class and "mutex_" not in engine_class
    assert "int32_t EngineUtil::SetParameter" in engine_cpp and "int32_t EngineUtil::WriteAudio" in engine_cpp
    assert '"server/base/adapter_callback_service.cpp"' in build and '"server/base/engine_util.cpp"' in build
    assert "if (intelligent_voice_framework_engine_enable)" in build
    assert "intelligent_voice_framework_engine_enable = true" in gni

    ipc_text = source_text["services/intell_voice_service/server/sa/intell_voice_service.cpp"]
    ipc_stub = source_text["services/intell_voice_service/server/sa/intell_voice_service_stub.h"]
    ipc_proxy = source_text["services/intell_voice_engine/proxy/intell_voice_service_proxy.cpp"]
    assert "class IntellVoiceService : public SystemAbility, public IntellVoiceServiceStub" in ipc_h if (ipc_h := source_text["services/intell_voice_service/server/sa/intell_voice_service.h"]) else False
    assert "VerifySystemPermission(OHOS_PERMISSION_INTELL_VOICE)" in ipc_text
    assert "HDI_INTELL_VOICE_SERVICE_CREATE_ENGINE" in ipc_proxy
    assert "CreateIntellVoiceEngine(type, engine)" in source(repo, CASES["CR-0305"]["path"])[0]

    results = [scan(repo, review_id, case) for review_id, case in CASES.items()]
    output = {
        "schema_version": 1,
        "task": "T50",
        "scope": "independent production CLI replay and source-context audit; no detector, test, fixture, or A0 edits",
        "source": {"repository": "openharmony/ai_intelligent_voice_framework", "commit": COMMIT,
                   "tree": TREE, "a0_snapshot_sha256": QUEUE_SNAPSHOT, "supporting_files": source_files},
        "scanner_checkout": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "a0_rows": a0,
        "replays": results,
        "source_review": {
            "CR-0301": "listener_ is initialized from the constructor argument and read by the callback implementation; callback instances are constructed in enroll, headset wakeup, high-power wakeup and wakeup engine code. Concurrent lifetime/dispatch overlap and caller impact are not established.",
            "CR-0302_to_0304": "The current shared_ptr detector reports engine_util.h lines 77, 78 and 86. They are assignment, null check/read, and reset of EngineUtil::adapter_. These operations appear in common base templates; the component has multiple derived engines and external call sites. Locking/serialization differs by caller and was not proven to dominate every same-instance operation. The base class itself declares no synchronization member for adapter_.",
            "build": "The pinned engine BUILD.gn includes the callback and engine utility implementation in engine_source when intelligent_voice_framework_engine_enable is enabled; the GNI default enables that feature. A product-specific resolved GN profile/image and runtime thread overlap were not established.",
            "CR-0305": "IPC capability-export finding reproduced at line 70. D48's pinned source review shows the concrete virtual factory checks MANAGE_INTELLIGENT_VOICE and the Stub exits on nonzero before export; this cross-file guard does not establish product caller grants, reachability, product build, capability impact, or a fixed-source comparison.",
        },
        "assessment": {"all_cases": "PARTIAL/BLOCK", "reason": "Source candidates and current CLI behavior are bound, but concurrency/reachability/product authorization and impact are not proven. No trusted vulnerable/fixed pair exists in these A0 rows.", "a0_mutated": False},
    }
    encoded = json.dumps(output, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    for item in results:
        print(f"PASS {item['review_id']}: {item['detector_id']} {item['detector_version']} parse={item['parse_status']} status={item['run_status']} finding={item['a0_root_candidate_reproduced']} line={item['a0_line']}")
    print("PASS T50: 345 A0 rows present; five selected source bindings and original statuses preserved")
    print("PASS T50: cross-file callback, lock/call, build and IPC factory context source-bound")
    print("PASS T50: every selected case remains PARTIAL/BLOCK; no detector/test/fixture/A0 mutation")
    if args.output:
        print(f"WROTE {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
