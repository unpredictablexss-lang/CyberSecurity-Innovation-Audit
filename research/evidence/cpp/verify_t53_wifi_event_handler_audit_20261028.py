#!/usr/bin/env python3
"""Reproduce and verify T53's source-bound Wi-Fi shared_ptr audit."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

COMMIT = "e336c82b3b107d87f68c5e0448cc246b50b53b38"
TREE = "edd28e23c84d17fa072f8501d7fe3dfbfa55498f"
REPOSITORY = "openharmony/communication_wifi"
TARGET = "wifi/utils/src/wifi_event_handler.cpp"
TARGET_BLOB = "859972d51001153749e1f3df5f8fc0bb5f5e3b7a"
TARGET_SHA256 = "f5b5de6a96ae54bbe3563bc93206fcb625c3f8d19c299d1b6f82fe1df7123f01"
QUEUE_IDS = [f"CR-{n:04d}" for n in range(317, 335)]
SUPPORTING = {
    "wifi/utils/inc/wifi_event_handler.h": "public API and unique_ptr owner",
    "wifi/utils/BUILD.gn": "production wifi_utils target and build-mode conditional",
    "wifi/test/wifi_utils/unittest/BUILD.gn": "unit-test target classification",
    "wifi/test/wifi_utils/unittest/wifi_event_handler_test.cpp": "sequential unit tests",
    "wifi/utils/src/wifi_timer.cpp": "representative production caller",
    "wifi/base/state_machine/src/handler.cpp": "representative production caller",
}


def git(repo: str, *args: str) -> bytes:
    return subprocess.check_output(["git", "--git-dir", repo, *args])


def get_source(repo: str, path: str) -> tuple[bytes, dict]:
    raw = git(repo, "show", f"{COMMIT}:{path}")
    return raw, {
        "blob": git(repo, "rev-parse", f"{COMMIT}:{path}").decode().strip(),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
    }


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source-git-dir", required=True)
    ap.add_argument("--source-repo-dir", required=True)
    ap.add_argument("--output-dir", type=Path, default=ROOT / "research/evidence/cpp")
    args = ap.parse_args()
    source_git = str(Path(args.source_git_dir))
    source_repo = Path(args.source_repo_dir)
    out_dir = args.output_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    require(git(source_git, "rev-parse", f"{COMMIT}^{{tree}}").decode().strip() == TREE,
            "pinned repository tree mismatch")
    queue_csv = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv"
    queue_json = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.json"
    with queue_csv.open(encoding="utf-8-sig", newline="") as f:
        rows = {r["queue_id"]: r for r in csv.DictReader(f)}
    qjson = json.loads(queue_json.read_text(encoding="utf-8"))
    qjson_rows = {r["queue_id"]: r for r in qjson["queue"]}
    require(len(rows) == 345 and len(qjson_rows) == 345, "A0 row count/uniqueness mismatch")
    require("CR-0335" in rows and rows["CR-0335"]["detector"] == "ohscanner.interface.ipc",
            "CR-0335 IPC boundary row missing or changed")

    target_raw, target_id = get_source(source_git, TARGET)
    require(target_id["blob"] == TARGET_BLOB and target_id["sha256"] == TARGET_SHA256,
            "pinned target blob/SHA mismatch")
    target_text = target_raw.decode("utf-8")
    require(target_text.splitlines()[241].strip() ==
            "eventRunner = AppExecFwk::EventRunner::Create(threadName);",
            "CR-0317 source line mismatch")
    source_ids = {}
    sources = {TARGET: target_text}
    for path in SUPPORTING:
        raw, identity = get_source(source_git, path)
        sources[path] = raw.decode("utf-8")
        source_ids[path] = identity

    with tempfile.TemporaryDirectory(prefix="t53-wifi-replay-") as tmp:
        raw_json = Path(tmp) / "cli.json"
        raw_md = Path(tmp) / "cli.md"
        cmd = [sys.executable, "-m", "src.cli.main", "ohscan-run",
               "--repo-dir", str(source_repo), "--repository", REPOSITORY,
               "--commit", COMMIT, "--include", TARGET,
               "--detector", "ohscanner.cpp.shared_ptr_race",
               "--json-out", str(raw_json), "--md-out", str(raw_md)]
        subprocess.run(cmd, cwd=ROOT, check=True, capture_output=True, text=True)
        cli = json.loads(raw_json.read_text(encoding="utf-8"))
        (out_dir / "t53_wifi_event_handler_cli_20261028.json").write_text(
            json.dumps(cli, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (out_dir / "t53_wifi_event_handler_cli_20261028.md").write_text(
            raw_md.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    runs = [r for r in cli["detector_runs"] if r.get("tool") == "ohscanner.cpp.shared_ptr_race"]
    require(len(runs) == 1, "expected one shared_ptr_race detector run")
    run = runs[0]
    findings = run["diagnostics"]
    require(run["tool_version"] == "0.5.1" and run["status"] == "completed",
            "unexpected detector version/status")
    require(cli["git_tree"] == TREE and cli["scope"]["declared_scope"] == [TARGET],
            "CLI scope/tree mismatch")
    require(cli["source_parsing"]["parsing_status"] == {"complete": 1},
            "target translation unit did not parse completely")
    require(len(findings) == 18, "expected 18 current findings")

    by_location = {(f["line"], f["column"], f["symbol"]): f for f in findings}
    audit_rows = []
    for qid in QUEUE_IDS:
        row = rows[qid]
        nested = qjson_rows[qid]
        require((row["repository"], row["commit"], row["tree"], row["path"], row["blob"],
                 row["source_sha256"], row["detector"], row["original_status"], row["queue_status"]) ==
                (REPOSITORY, COMMIT, TREE, TARGET, TARGET_BLOB, TARGET_SHA256,
                 "ohscanner.cpp.shared_ptr_race", "not_testable", "paused_pending_evidence"),
                f"A0 row identity or state changed: {qid}")
        original = nested["original_record"]
        line, column, symbol = int(row["line"]), int(original["column"]), original["symbol"]
        finding = by_location.get((line, column, symbol))
        require(finding is not None, f"no exact current CLI finding for {qid} at {line}:{column} {symbol}")
        audit_rows.append({
            "queue_id": qid,
            "original_candidate_id": row["candidate_id"],
            "source": {"path": TARGET, "line": line, "column": column, "symbol": symbol,
                       "line_text": original["source_binding"]["line_text"]},
            "original_status": row["original_status"],
            "queue_status": row["queue_status"],
            "current_finding": {"diagnostic_id": finding["diagnostic_id"],
                                "rule_id": finding["rule_id"], "symbol": finding["symbol"],
                                "line": finding["line"], "column": finding["column"],
                                "evidence_type": finding["evidence_type"]},
            "a0_state_mutated": False,
        })

    header = sources["wifi/utils/inc/wifi_event_handler.h"]
    build = sources["wifi/utils/BUILD.gn"]
    test_build = sources["wifi/test/wifi_utils/unittest/BUILD.gn"]
    test_source = sources["wifi/test/wifi_utils/unittest/wifi_event_handler_test.cpp"]
    regular_branch = target_text[target_text.index("#else\nclass WifiEventHandler::WifiEventHandlerImpl", target_text.index("#elif WIFI_FFRT_ENABLE")):target_text.index("#endif\n\nWifiEventHandler::WifiEventHandler", target_text.index("#elif WIFI_FFRT_ENABLE"))]
    ffrt_branch = target_text[target_text.index("#elif WIFI_FFRT_ENABLE"):target_text.index("#else\nclass WifiEventHandler::WifiEventHandlerImpl", target_text.index("#elif WIFI_FFRT_ENABLE"))]
    require("std::lock_guard<ffrt::mutex> lock(eventQurueMutex);" in ffrt_branch,
            "FFRT branch synchronization not located")
    require("eventRunner->Stop();" in regular_branch and "eventRunner.reset();" in regular_branch
            and "eventHandler.reset();" in regular_branch, "normal branch teardown sites missing")
    require("std::lock_guard" not in regular_branch and "std::mutex" not in regular_branch,
            "unexpected lock in normal EventHandler branch")
    require("std::unique_ptr<WifiEventHandlerImpl> ptr;" in header,
            "public owner type no longer matches reviewed structure")
    require('ohos_shared_library("wifi_utils")' in build
            and '"src/wifi_event_handler.cpp"' in build
            and "install_enable = true" in build,
            "production target/source registration missing")
    require('ohos_unittest("wifi_utils_test")' in test_build or "wifi_event_handler_test.cpp" in test_build,
            "unit-test registration not found")
    require("PostAsyncTask" in sources["wifi/utils/src/wifi_timer.cpp"]
            and "PostAsyncTask" in sources["wifi/base/state_machine/src/handler.cpp"],
            "representative production caller evidence missing")

    result = {
        "schema_version": 1,
        "task": "T53",
        "record_ids": QUEUE_IDS,
        "assessment": "PARTIAL/BLOCK",
        "classification": "all 18 syntax candidates independently reproduce; this is not proof of a data race or security impact",
        "source": {
            "repository": REPOSITORY, "commit": COMMIT, "tree": TREE,
            "target": {"path": TARGET, **target_id},
            "supporting_sources": source_ids,
        },
        "scanner": {
            "command": "python -m src.cli.main ohscan-run --repo-dir <exact-checkout> --repository openharmony/communication_wifi --commit e336c82b3b107d87f68c5e0448cc246b50b53b38 --include wifi/utils/src/wifi_event_handler.cpp --detector ohscanner.cpp.shared_ptr_race",
            "detector_id": run["tool"], "detector_version": run["tool_version"],
            "profile": cli.get("profile_id"), "run_status": run["status"],
            "snapshot_sha256": cli["snapshot_sha256"], "selected_files": cli["scope"]["selected_source_files"],
            "selected_bytes": cli["scope"]["selected_source_bytes"], "scope_loc": run["scope_loc"],
            "parse_status": cli["source_parsing"]["parsing_status"],
            "finding_count": len(findings), "elapsed_seconds": run["elapsed_seconds"],
        },
        "source_review": {
            "normal_eventhandler_branch": {
                "members": ["eventRunner", "eventHandler"],
                "constructor": "Create(threadName), then make_shared<EventHandler>(eventRunner);",
                "destructor": "Stop runner, then reset eventRunner and eventHandler.",
                "accesses": "PostSyncTask/PostAsyncTask/RemoveAsyncTask perform null checks then invoke methods through eventHandler without a branch-local lock.",
                "callbacks_and_threads": "PostTask hands callbacks to EventHandler; normal producer/callback overlap and object teardown ordering are not established from this translation unit.",
                "lock_status": "No explicit lock around normal-branch shared_ptr members. This alone does not prove unsynchronized concurrent access.",
            },
            "ffrt_branch": "The separate WIFI_FFRT_ENABLE implementation uses eventQueueMutex in constructor, destructor, and event queue operations; GN selects this branch conditionally.",
            "build": "wifi/utils/BUILD.gn includes this file in install-enabled ohos_shared_library(\"wifi_utils\"); WIFI_FFRT_ENABLE is conditional on wifi_ffrt_enable. Exact product profile/config selection is not bound.",
            "callers": "Pinned wifi_timer.cpp and base/state_machine handler.cpp use the task-posting API; their ownership/scheduling does not establish same-object overlap with destruction.",
            "unit_tests": "Pinned wifi_utils unittest target registers wifi_event_handler_test.cpp; its methods exercise posting behavior but do not provide a target-derived concurrent destructor race harness.",
        },
        "rows": audit_rows,
        "a0_reconciliation": {
            "queue_rows": len(rows), "unique_queue_ids": len(rows),
            "audited_rows": len(audit_rows), "cr0335_excluded": True,
            "original_status_counts": {"not_testable": 18},
            "queue_status_counts": {"paused_pending_evidence": 18},
            "original_states_unchanged": True,
        },
        "limitations": [
            "No trusted vulnerable/fixed pair or target-derived concurrent harness is bound.",
            "The applicable product build branch and profile selection are unknown.",
            "Same-object overlapping public method calls versus destruction, external owner synchronization, and runtime impact are not established.",
            "A complete parse and 18 reproduced findings are syntax evidence only; they do not confirm a race or prove safety.",
            "CR-0335 is an IPC detector/source-line case and was intentionally excluded.",
        ],
    }
    json_path = out_dir / "t53_wifi_event_handler_shared_ptr_audit_20261028.json"
    json_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    report = f"""# T53 — Wi-Fi event handler shared_ptr 独立审计（CR-0317–CR-0334）

## 结论

当前 `ohscan-run` 使用 `ohscanner.cpp.shared_ptr_race` 0.5.1 对 A0 精确源文件运行：1 个文件、386 LOC、完整解析、18 条 finding，与 18 个 A0 行按行号/列号/成员名全部对应。结论为 **PARTIAL/BLOCK**：这证明扫描器在该源码对象上复现了语法候选，不证明存在数据竞争、可利用路径或安全影响，也不证明安全。没有可信漏洞/修复源码对照或目标派生并发 harness。

## 来源绑定与范围

- 仓库：`{REPOSITORY}`
- commit/tree：`{COMMIT}` / `{TREE}`
- 目标：`{TARGET}`，blob `{target_id['blob']}`，SHA-256 `{target_id['sha256']}`，{target_id['bytes']} bytes
- CLI：`{run['tool']}` {run['tool_version']}，scope 仅目标文件，解析 `complete`，18 findings，snapshot `{cli['snapshot_sha256']}`，耗时 {run['elapsed_seconds']:.4f}s
- 范围明确排除 CR-0335（`ohscanner.interface.ipc` 的另一源行/检测器）。A0 仍为 345 行，所审 18 行均保留 `not_testable / paused_pending_evidence`。

## 源码与构建核验

这 18 个候选都落在非 Lite、非 FFRT 的 `AppExecFwk::EventHandler` 分支。`eventRunner` 和 `eventHandler` 在构造时初始化，析构时先停止 runner 再 reset 两个 shared_ptr；同步/异步投递和任务移除方法直接通过 `eventHandler` 调用，普通分支没有成员锁。类公开 API 的 `ptr` 是 `unique_ptr<WifiEventHandlerImpl>`。Async callbacks 由 EventHandler 投递到其线程；仅凭本文件看不到 producer 与 callback、以及 API 调用与对象析构的真实重叠顺序。

另一 `WIFI_FFRT_ENABLE` 分支用 `eventQurueMutex` 包护构造、析构及队列访问。GN 将目标源文件加入 install-enabled `ohos_shared_library("wifi_utils")`，并根据 `wifi_ffrt_enable` 选择 FFRT 或 EventHandler 分支；精确产品配置/目标镜像未绑定。Pinned callers 包括 `wifi_timer.cpp` 和 state-machine `handler.cpp`，但调用拓扑不能证明同一实例与析构并发。unit test 注册 `wifi_event_handler_test.cpp`，未提供产品派生并发销毁 harness。

因此目前没有足够证据断言存在或不存在实际竞态。应保留原 A0 状态，后续最小补证是绑定产品 profile 的 GN 配置，再追踪同一实例的所有权/析构与所有投递 API 的线程交叠；若仍无法证明，则继续 PARTIAL/BLOCK。

## 每行对照

| A0 ID | 行:列 | 成员 | 当前 finding |
|---|---:|---|---|
"""
    for row in audit_rows:
        report += (f"| {row['queue_id']} | {row['source']['line']}:{row['source']['column']} | "
                   f"`{row['source']['symbol']}` | `{row['current_finding']['diagnostic_id']}` |\n")
    report += "\n机器记录：`t53_wifi_event_handler_shared_ptr_audit_20261028.json`；原始 CLI：`t53_wifi_event_handler_cli_20261028.json` 与 `.md`；重放/校验：`verify_t53_wifi_event_handler_audit_20261028.py`。\n"
    (out_dir / "t53_wifi_event_handler_shared_ptr_audit_20261028.md").write_text(report, encoding="utf-8")
    print("PASS T53: exact commit/tree/blob/SHA for all 18 A0 source rows")
    print("PASS T53: current production ohscan-run v0.5.1; 18/18 exact location/member findings; complete parse")
    print("PASS T53: source branch, lock, callbacks, API callers, production and test GN context reviewed")
    print("PASS T53: all 345 A0 queue IDs reconcile; original states unchanged; CR-0335 excluded")
    print(json.dumps({"audit": str(json_path), "finding_count": len(findings),
                      "parse_status": cli["source_parsing"]["parsing_status"],
                      "snapshot_sha256": cli["snapshot_sha256"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
