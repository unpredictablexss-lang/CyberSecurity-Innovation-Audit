from __future__ import annotations

import csv
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "research/evidence/cpp"
QUEUE = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv"
RAW = EVIDENCE / "t41_faultloggerd_tail_cli_20261024.json"
OUT = EVIDENCE / "t41_faultloggerd_tail_audit_20261024.json"
REPORT = EVIDENCE / "t41_faultloggerd_tail_audit_20261024.md"
SOURCE_ROOT = Path(r"D:\openHarmonyScanner\tmp\t40-faultloggerd-source-20261024")
REPO = "openharmony/hiviewdfx_faultloggerd"
COMMIT = "50c7dffc057a32987d5eeb7626c20e1b3717c77b"
TREE = "8b54f17921ba15ff306bcbef280078003a7b1055"
IDS = [f"CR-{n:04d}" for n in range(161, 174)]
SCOPE = [
    "tools/process_dump/dfx_process.h",
    "tools/process_dump/dfx_thread.h",
    "tools/process_dump/minidump_parser/include/minidump_parser.h",
    "tools/process_dump/minidump_parser/include/minidump_stream.h",
]
BUILD_FILES = ["tools/process_dump/BUILD.gn", "tools/process_dump/minidump_parser/BUILD.gn"]
CONTEXT_FILES = [
    "tools/process_dump/dfx_process.cpp",
    "tools/process_dump/dfx_thread.cpp",
    "tools/process_dump/minidump_dumper.cpp",
    "tools/process_dump/minidump_parser/minidump_parser.cpp",
    "tools/process_dump/minidump_parser/minidump_memory.cpp",
    "tools/process_dump/minidump_parser/minidump_thread.cpp",
]


def git(*args: str, binary: bool = False) -> str | bytes:
    result = subprocess.check_output(["git", "-C", str(SOURCE_ROOT), *args])
    return result if binary else result.decode("utf-8").strip()


def identity(path: str) -> dict[str, str | int]:
    data = git("show", f"{COMMIT}:{path}", binary=True)
    assert isinstance(data, bytes)
    return {"path": path, "blob": str(git("rev-parse", f"{COMMIT}:{path}")),
            "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def main() -> None:
    assert git("rev-parse", "HEAD") == COMMIT
    assert git("rev-parse", f"{COMMIT}^{{tree}}") == TREE
    rows = list(csv.DictReader(QUEUE.open(encoding="utf-8-sig", newline="")))
    assert len(rows) == 345 and len({row["queue_id"] for row in rows}) == 345
    by_id = {row["queue_id"]: row for row in rows}
    selected = [by_id[i] for i in IDS]
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    assert (raw["repository"], raw["commit"], raw["git_tree"]) == (REPO, COMMIT, TREE)
    run = raw["detector_runs"][0]
    assert (run["tool"], run["tool_version"], run["status"]) == (
        "ohscanner.cpp.shared_ptr_race", "0.5.1", "completed")
    diagnostics = {(d["file"], int(d["line"])): d for d in run["diagnostics"]}
    file_ids = {p: identity(p) for p in SCOPE}
    build_ids = {p: identity(p) for p in BUILD_FILES}
    context_ids = {p: identity(p) for p in CONTEXT_FILES}
    items = []
    for row in selected:
        assert (row["repository"], row["commit"], row["tree"]) == (REPO, COMMIT, TREE)
        assert row["original_status"] == "not_testable"
        assert row["queue_status"] == "paused_pending_evidence"
        p, line = row["path"], int(row["line"])
        src = git("show", f"{COMMIT}:{p}", binary=True)
        assert isinstance(src, bytes)
        assert hashlib.sha256(src).hexdigest() == row["source_sha256"].lower()
        assert file_ids[p]["blob"] == row["blob"]
        text = src.decode("utf-8").splitlines()[line - 1].strip()
        diag = diagnostics.get((p, line))
        items.append({
            "queue_id": row["queue_id"], "candidate_id": row["candidate_id"],
            "path": p, "line": line, "line_text": text,
            "source": file_ids[p], "a0_source_sha256": row["source_sha256"].lower(),
            "original_status": row["original_status"], "queue_status": row["queue_status"],
            "parse_status": raw["source_parsing"]["parsing_status"].get("complete", 0) and "complete",
            "current_cli": {"exact_line_finding": diag is not None,
                            "diagnostic_id": diag.get("diagnostic_id") if diag else None},
            "assessment": "PARTIAL",
        })
    assert len(items) == 13
    exact = sum(i["current_cli"]["exact_line_finding"] for i in items)
    report = f"""# T41 独立审计：faultloggerd shared_ptr_race CR-0161–CR-0173

- 基线：`1ebe2d809719cc7b445fe6e723c452e0634c8dd3`；输入源：`{COMMIT}` / tree `{TREE}`。
- 当前 CLI：`ohscanner.cpp.shared_ptr_race 0.5.1`，`light-ast`，4 个目标头文件、完整解析 4/4，7 条诊断；13 个 A0 行中 {exact}/13 精确匹配 finding。完整逐行映射、blob/SHA 和 CLI ID 见同名 JSON。
- `{SCOPE[0]}:74`（CR-0161）是 T40 的额外行 finding，本轮确认它确属新增 A0 尾部行。T40 的 `SetMaps` 调用方证据仅涉及 `LocalThreadContextMix::maps_`（CR-0143）；不适用于 DfxProcess、DfxThread 或 minidump parser 对象。
- `dfx_process.h` 的 getter/setter 与 `dfx_thread.h` 的 stack buffer / ProcessInfo getter 只表明成员读写接口；已见生产调用集中在 processdump 的请求初始化和 minidump 处理路径。没有证据证明同一个对象同时跨线程调用这些方法，类本身也没有针对 shared_ptr 成员的锁。
- minidump parser 对象经 `processdump` 的 `minidump_parser` source_set 消费，属于 production-capable 构建路径。`MinidumpParser::streamMapMutex_` 保护 stream map 操作，但并不自动保护其他 `MinidumpStream` 子类的 vector/ref 成员访问。此片段未建立同一流对象并发 Read 与 getter 的重叠。
- 无可信固定版或产品级线程/入口证据；不将完整语法解析、无精确 finding 或 production-capable BUILD 声明解释为安全或漏洞确认。13 项均保留 `PARTIAL` 和 A0 原状态。

## 逐项回放

| ID | Source line | CLI exact finding | Status |
|---|---|---:|---|
"""
    for item in items:
        report += f"| {item['queue_id']} | `{item['path']}:{item['line']}` | {'yes' if item['current_cli']['exact_line_finding'] else 'no'} | PARTIAL |\n"
    report += """
## 构建与对象上下文

- `tools/process_dump/BUILD.gn` 将 `processdump_sources` 纳入 `ohos_executable("processdump")` 且 `install_enable = true`；其依赖包含 `minidump_parser:minidump_parser`。
- `tools/process_dump/minidump_parser/BUILD.gn` 定义 `ohos_source_set("minidump_parser")`，由 processdump 依赖。BUILD 只能证明 production-capable target 收录，不证明具体产品 manifest、安装状态或入口可达性。
- `DfxProcess::regs_`（CR-0161）、`DfxThread::stackBuf_`（CR-0162/0163）、`DfxThread::processInfo_`（CR-0164）和 minidump stream/parser shared_ptr（CR-0165–0173）均是不同对象/成员。没有将 T40 LocalThreadContextMix singleton 的 SetMaps 并发结论外推到这些对象。
- CR-0165–0168 为 subject/stream map 相关初始化或 getter；CR-0169 为 `MinidumpContext::SetContextARM64` 内部赋值；CR-0170/0172 返回 vector 引用，CR-0171 返回 vector 拷贝，CR-0173 返回 owned vector shared_ptr。并发安全还取决于实例发布后 Read/访问是否重叠；现有固定证据不足以判定。

## 来源与复验

- 精确 scope 文件、BUILD 文件、调用上下文文件均记录 Git blob、SHA-256 和字节数于 JSON。
- 当前 CLI 原始输出：`t41_faultloggerd_tail_cli_20261024.json`。
- 运行：`python research/evidence/cpp/t41_faultloggerd_tail_audit_20261024.py`；验证：`python research/evidence/cpp/verify_t41_faultloggerd_tail_audit_20261024.py`。
"""
    OUT.write_text(json.dumps({
        "schema_version": "t41-faultloggerd-tail-audit-v1", "task": "T41",
        "integration_base": "1ebe2d809719cc7b445fe6e723c452e0634c8dd3",
        "target_source": {"repository": REPO, "commit": COMMIT, "tree": TREE},
        "scanner": {"tool": run["tool"], "version": run["tool_version"],
                    "status": run["status"], "profile": raw["profile_id"],
                    "scope_files": run["scope_files"], "scope_loc": run["scope_loc"],
                    "parse_status": raw["source_parsing"]["parsing_status"],
                    "diagnostic_count": run["diagnostic_count"],
                    "elapsed_seconds": run["elapsed_seconds"], "raw": RAW.name},
        "source_file_identities": list(file_ids.values()),
        "build_file_identities": list(build_ids.values()),
        "reviewed_context_file_identities": list(context_ids.values()),
        "a0_rows": items, "exact_line_findings": exact,
        "additional_cli_findings_outside_group": [
            {"path": d["file"], "line": d["line"], "diagnostic_id": d["diagnostic_id"]}
            for d in run["diagnostics"] if (d["file"], int(d["line"])) not in
            {(x["path"], x["line"]) for x in items}],
        "a0_unchanged": {"queue_rows": len(rows), "group_rows": len(items),
                         "group_original_status_counts": {"not_testable": len(items)},
                         "group_queue_status_counts": {"paused_pending_evidence": len(items)},
                         "modified": False},
        "overall_disposition": "PARTIAL",
        "limitations": ["No trusted fixed source", "No product manifest/runtime entry or same-object overlap proof",
                         "Complete parse is syntactic coverage only"]
    }, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    REPORT.write_text(report, encoding="utf-8")
    print(f"Wrote T41 report for {len(items)} rows; exact findings {exact}/13")


if __name__ == "__main__":
    main()
