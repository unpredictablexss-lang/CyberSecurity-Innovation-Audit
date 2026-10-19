from __future__ import annotations

import csv
import hashlib
import json
import subprocess
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "research/evidence/cpp"
QUEUE = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv"
RAW = EVIDENCE / "t40_faultloggerd_sharedptr_cli_20261024.json"
OUT = EVIDENCE / "t40_faultloggerd_sharedptr_audit_20261024.json"
REPORT = EVIDENCE / "t40_faultloggerd_sharedptr_audit_20261024.md"
SOURCE_ROOT = Path(r"D:\openHarmonyScanner\tmp\t40-faultloggerd-source-20261024")
REPO = "openharmony/hiviewdfx_faultloggerd"
COMMIT = "50c7dffc057a32987d5eeb7626c20e1b3717c77b"
TREE = "8b54f17921ba15ff306bcbef280078003a7b1055"
IDS = [f"CR-{number:04d}" for number in range(119, 161)]
BUILD_FILES = [
    "interfaces/innerkits/backtrace/BUILD.gn",
    "interfaces/innerkits/stack_printer/BUILD.gn",
    "interfaces/innerkits/unwinder/BUILD.gn",
    "interfaces/innerkits/unwinder_refactor/BUILD.gn",
    "tools/process_dump/BUILD.gn",
]
REVIEW_CONTEXT_FILES = [
    "tools/process_dump/lite_process_dumper.cpp",
    "tools/process_dump/minidump_dumper.cpp",
    "interfaces/innerkits/unwinder_refactor/src/unwind_local/local_unwinder.cpp",
    "interfaces/innerkits/unwinder/src/unwind_local/thread_context.cpp",
]
INCLUDE_PATHS = [
    "interfaces/innerkits/backtrace/fp_backtrace.cpp",
    "interfaces/innerkits/stack_printer/src/stack_printer.cpp",
    "interfaces/innerkits/unwinder/include/dfx_accessors.h",
    "interfaces/innerkits/unwinder/include/dfx_elf_parser.h",
    "interfaces/innerkits/unwinder/include/dwarf_cfa_instructions.h",
    "interfaces/innerkits/unwinder/include/dwarf_op.h",
    "interfaces/innerkits/unwinder/include/thread_context.h",
    "interfaces/innerkits/unwinder/include/unwind_entry_parser.h",
    "interfaces/innerkits/unwinder_refactor/include/unwinder_base.h",
    "tools/process_dump/coredump/coredump_note_segment_writer.h",
    "tools/process_dump/dfx_process.h",
]


def git(*args: str, binary: bool = False) -> str | bytes:
    result = subprocess.check_output(["git", "-C", str(SOURCE_ROOT), *args])
    return result if binary else result.decode("utf-8").strip()


def identity(path: str) -> dict[str, str | int]:
    data = git("show", f"{COMMIT}:{path}", binary=True)
    assert isinstance(data, bytes)
    return {
        "path": path,
        "blob": str(git("rev-parse", f"{COMMIT}:{path}")),
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
    }


def main() -> None:
    assert git("rev-parse", "HEAD") == COMMIT
    assert git("rev-parse", "HEAD^{tree}") == TREE
    with QUEUE.open(encoding="utf-8-sig", newline="") as stream:
        all_rows = list(csv.DictReader(stream))
    assert len(all_rows) == 345
    assert len({row["queue_id"] for row in all_rows}) == 345
    by_id = {row["queue_id"]: row for row in all_rows}
    rows = [by_id[queue_id] for queue_id in IDS]
    assert len(rows) == 42

    raw = json.loads(RAW.read_text(encoding="utf-8"))
    assert (raw["repository"], raw["commit"], raw["git_tree"]) == (REPO, COMMIT, TREE)
    run = raw["detector_runs"][0]
    assert (run["tool"], run["tool_version"], run["status"]) == (
        "ohscanner.cpp.shared_ptr_race", "0.5.1", "completed"
    )
    diagnostics = {(item["file"], int(item["line"])): item for item in run["diagnostics"]}
    paths = sorted({row["path"] for row in rows})
    source_files = {path: identity(path) for path in paths}
    assert len(paths) == 11
    build_files = {path: identity(path) for path in BUILD_FILES}
    context_files = {path: identity(path) for path in REVIEW_CONTEXT_FILES}

    items = []
    for row in rows:
        path = row["path"]
        file_id = source_files[path]
        assert (row["repository"], row["commit"], row["tree"]) == (REPO, COMMIT, TREE)
        assert row["blob"] == file_id["blob"]
        assert row["source_sha256"].lower() == file_id["sha256"]
        assert (row["original_status"], row["queue_status"]) == (
            "not_testable", "paused_pending_evidence"
        )
        raw_source = git("show", f"{COMMIT}:{path}", binary=True)
        assert isinstance(raw_source, bytes)
        lines = raw_source.decode("utf-8").splitlines()
        line = int(row["line"])
        finding = diagnostics.get((path, line))
        items.append({
            "queue_id": row["queue_id"],
            "a0_candidate_id": row["candidate_id"],
            "source": {**file_id, "repository": REPO, "commit": COMMIT, "tree": TREE},
            "candidate_line": line,
            "candidate_line_text": lines[line - 1].strip(),
            "current_cli": {
                "exact_line_finding": finding is not None,
                "diagnostic_id": finding["diagnostic_id"] if finding else None,
                "rule_id": finding["rule_id"] if finding else None,
                "symbol": finding.get("symbol") if finding else None,
                "evidence_type": finding.get("evidence_type") if finding else None,
                "finding_line": finding["line"] if finding else None,
                "source_sha256": finding["source_sha256"] if finding else None,
            },
            "a0_state": {
                "original_status": row["original_status"],
                "queue_status": row["queue_status"],
                "recorded_parse_status": row["source_file_parse_status"],
            },
            "disposition": "PARTIAL",
        })

    result = {
        "schema_version": "t40-faultloggerd-sharedptr-independent-audit-v1",
        "task": "T40",
        "integration_base": "c5c7ea0989c91b884f96ecd1527aad57a7f3a635",
        "scanner": {
            "detector": run["tool"],
            "version": run["tool_version"],
            "status": run["status"],
            "profile": raw["profile_id"],
            "scope_files": raw["scope"]["selected_source_files"],
            "scope_loc": run["scope_loc"],
            "parse": raw["source_parsing"]["parsing_status"],
            "diagnostic_count": run["diagnostic_count"],
            "validated_vulnerability": raw["validated_vulnerability"],
            "elapsed_seconds": run["elapsed_seconds"],
            "snapshot_sha256": raw["snapshot_sha256"],
            "raw": RAW.name,
            "command": (
                "python -m src.cli.main ohscan-run --repo-dir "
                + str(SOURCE_ROOT)
                + " --repository " + REPO + " --commit " + COMMIT
                + " " + " ".join("--include " + path for path in INCLUDE_PATHS)
                + " --detector ohscanner.cpp.shared_ptr_race"
            ),
        },
        "target_source": {"repository": REPO, "commit": COMMIT, "tree": TREE},
        "source_file_identities": list(source_files.values()),
        "build_file_identities": list(build_files.values()),
        "reviewed_context_file_identities": list(context_files.values()),
        "build_review": {
            "targets": [
                {"build_file": "interfaces/innerkits/backtrace/BUILD.gn", "production_target": "ohos_shared_library(\"libbacktrace_local\")", "includes": "fp_backtrace.cpp through backtrace_local_sources", "testonly": False},
                {"build_file": "interfaces/innerkits/stack_printer/BUILD.gn", "production_target": "ohos_shared_library(\"libstack_printer\")", "includes": "src/stack_printer.cpp", "testonly": False},
                {"build_file": "interfaces/innerkits/unwinder/BUILD.gn", "production_target": "libunwinder variants", "includes": "thread_context.cpp and dwarf_op.cpp; relevant headers consumed by these targets", "testonly": False},
                {"build_file": "interfaces/innerkits/unwinder_refactor/BUILD.gn", "production_target": "libunwinder_refactor variants", "includes": "refactored base/header implementation and reused unwinder sources", "testonly": False},
                {"build_file": "tools/process_dump/BUILD.gn", "production_target": "process_info_src / process_dump targets", "includes": "dfx_process.cpp and arm64 coredump writer source", "testonly": False},
            ],
            "limitations": [
                "GN declarations show production-capable targets, not that a specific product manifest/profile includes them.",
                "No build was performed; target CPU, defines, feature flags, and product configuration were not frozen.",
                "Relevant targets are not declared as testonly fuzz targets; this establishes source/build classification only, not runtime reachability.",
            ],
        },
        "source_concurrency_review": {
            "method": "Read exact-source declarations, assignments, reads, call sites, mutexes/atomics, and adjacent GN source lists; no runtime or TSan claim.",
            "findings": [
                {"family": "FpBacktraceImpl::maps_ (CR-0119–0123)", "facts": "Assigned from DfxMaps::Create in Init before CreateInstance returns; subsequently read by BacktraceFromFp and SymbolicAddress. SymbolicAddress serializes its cache/unwind path with mutex_; no later maps_ assignment found in this object.", "thread_overlap_proven": False, "assessment": "Creation/publication ordering is consistent with one-time initialization, but API ownership and external lifetime are not fully bound; syntax candidates do not establish a race."},
                {"family": "StackPrinter::Impl (CR-0124)", "facts": "Queue line 127 is the Impl constructor initializer and contains no shared_ptr. The same source has SetUnwindInfo assigning unwinder_/maps_ without mutex_; GetFullStack/GetTreeStack read them without mutex_, while GetHeaviestStack locks only after an initial null check.", "thread_overlap_proven": False, "assessment": "This row is a source/model mismatch: current CLI has no diagnostic at the A0 line and the row points to a constructor initializer, not the unsynchronized member operations. The separate access pattern is an independent review lead; no caller lifecycle/thread-safety contract establishes concurrent use."},
                {"family": "DfxAccessorsCustomize / ElfParser / Dwarf* / UnwindEntryParser (CR-0125–0142)", "facts": "Rows are constructor initialization or reads through the held memory/accessor objects. No post-construction reassignment of those shared_ptr members is shown at the queue lines; exact selected files parse completely.", "thread_overlap_proven": False, "assessment": "Shared ownership/copying alone does not establish a pointee race; pointee synchronization and object sharing remain unproven."},
                {"family": "LocalThreadContextMix::maps_ (CR-0143)", "facts": "Singleton. Production-capable write sites: CollectThreadContext, ReleaseCollectThreadContext, and SetMaps. SetMaps call sites are tools/process_dump/lite_process_dumper.cpp:362 and minidump_dumper.cpp:514; Collect/Release are called at local_unwinder.cpp:176-181 by LocalUnwinder::DoUnwindLocalByOtherTid. Reads: GetMapByPc, FindUnwindTable, AccessMem, GetMaps in thread_context.cpp. Assignment sites do not hold mtx_; Collect sets maps before signal delivery and waits for a condition-variable status before returning; Release clears maps while holding mtx_. The two process-dumper call sites are under their respective production-capable process dump targets.", "thread_overlap_proven": False, "assessment": "The singleton shared state and unsynchronized SetMaps writes are real source facts and justify a focused follow-up. The exact product service call topology and whether Lite/Minidump dumper instances can overlap with each other or LocalUnwinder collection were not proven from this component checkout; do not promote to a data race."},
                {"family": "UnwinderSharedState (CR-0145–0156)", "facts": "UnwinderBase wrappers write/read shared state regs/maps and expose references; internal components share the state. No lock is present at the queue lines.", "thread_overlap_proven": False, "assessment": "Per-Unwinder ownership and external concurrent calls are not established; state sharing inside one object alone is not concurrent access."},
                {"family": "CoredumpThread / DfxProcess members (CR-0157–0160)", "facts": "CoredumpThread::Init assigns keyRegs_; DfxProcess setters/getters assign/expose keyThread_ and regs_. Call sites use process-local dump objects and then populate/report them; no cross-thread access contract or same-object concurrent mutation is established from these files.", "thread_overlap_proven": False, "assessment": "Candidate syntax does not prove sharing across threads; keep unresolved pending service-level object lifetime evidence."},
            ],
            "global_limitations": [
                "No product build/profile or caller thread topology is pinned.",
                "No unambiguous same-object concurrent read/write interval has been established, including for the LocalThreadContextMix singleton; its production-capable call sites are recorded above but product service serialization is not pinned.",
                "No fixed-source, safe-control, or product-labeled ground truth was available in this task scope.",
                "Complete parsing of 11 selected source files does not imply complete repository or product semantic coverage.",
            ],
        },
        "a0_rows": items,
        "a0_unchanged": {
            "queue_rows": len(all_rows),
            "group_rows": len(items),
            "group_original_status_counts": dict(Counter(row["original_status"] for row in rows)),
            "group_queue_status_counts": dict(Counter(row["queue_status"] for row in rows)),
            "modified": False,
        },
        "overall_disposition": "PARTIAL",
    }
    OUT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    cli_findings = sum(item["current_cli"]["exact_line_finding"] for item in items)
    lines = [
        "# T40 独立审计：faultloggerd shared_ptr_race CR-0119–CR-0160",
        "",
        f"- 整合基线：`{result['integration_base']}`；审计提交：`{COMMIT}`，tree `{TREE}`。",
        f"- 范围：42 个 A0 ID，覆盖 {len(paths)} 个源码文件；文件 blob/SHA、BUILD blob/SHA 和逐 ID 证据见同名 JSON。",
        f"- 当前 CLI：`{run['tool']} {run['tool_version']}`，profile `{raw['profile_id']}`，{run['status']}；解析 {raw['source_parsing']['parsing_status']}，11 条 diagnostics，{cli_findings}/42 个 A0 行精确对应 finding。另有 `tools/process_dump/dfx_process.h:74` finding 不属于这 42 个 A0 ID。",
        "- 结论：全部保留 `PARTIAL / not_testable / paused_pending_evidence`。Finding 是 shared_ptr 语法候选，不等同同一对象并发读写、真实竞态或漏洞。A0 原队列未修改。",
        "",
        "## 逐 ID 对账",
        "",
        "| A0 ID | 源文件:行 | A0 行摘要 | 当前 CLI 精确 finding | 结论 |",
        "|---|---|---|---|---|",
    ]
    for item in items:
        finding = item["current_cli"]
        location = f"`{item['source']['path']}:{item['candidate_line']}`"
        found = f"`{finding['diagnostic_id']}`" if finding["exact_line_finding"] else "无（不是 safe 结论）"
        excerpt = item["candidate_line_text"].replace("|", "\\|")
        lines.append(f"| {item['queue_id']} | {location} | `{excerpt}` | {found} | PARTIAL |")
    lines += [
        "",
        "## 源码并发与构建边界",
        "",
        "- **FpBacktraceImpl `maps_`（CR-0119–0123）**：`Init()` 建立并写入，`CreateInstance()` 初始化成功后才返回对象；之后 `BacktraceFromFp` 读取，`SymbolicAddress` 在 `mutex_` 下读并操作缓存。没有发现对象发布后的第二次 maps_ 写入。对象生命周期/外部调用线程契约未绑定，因此不据此判安全或竞态。",
        "- **StackPrinter（CR-0124）**：A0 行 127 是空构造函数初始化列表，当前 CLI 无精确 finding，属于 A0 source/model mismatch。同文件的 `SetUnwindInfo` 对 `unwinder_`/`maps_` 无锁赋值；`GetFullStack`/`GetTreeStack` 有无锁读取，`GetHeaviestStack` 的初始空值读取也在锁外。这是单独的潜在线索，但当前没有证明调用者共享同一对象并重叠调用。",
        "- **DfxAccessors / ElfParser / Dwarf / UnwindEntryParser（CR-0125–0142）**：队列行对应构造初始化或通过已持有对象读取；shared_ptr 的复制/持有本身不证明 pointee 并发访问。未在这些行证明同一 shared_ptr member 有并发赋值和读取。",
        "- **LocalThreadContextMix `maps_`（CR-0143）**：它是函数静态 singleton。写入点包括 `CollectThreadContext`、`SetMaps`、`ReleaseCollectThreadContext`；读取点包括 `GetMapByPc`、`FindUnwindTable`、`AccessMem`、`GetMaps`。`SetMaps` 的生产能力调用见 `LiteProcessDumper::Unwind` 和 `MinidumpDumper::UnwindProcess`；`Collect/Release` 来自 `LocalUnwinder::DoUnwindLocalByOtherTid`。`SetMaps`/`Collect` 赋值不在 `mtx_` 临界区；Collect 信号/条件变量交接及 Release 持锁清理也必须结合整体调用序列判断。共享 singleton 与未锁写入是真实源码事实；是否有产品服务并行调用/与读操作重叠仍未由固定产品配置和调用拓扑证明，故只列 follow-up，不升级为 race。",
        "- **UnwinderSharedState（CR-0145–0156）**：内部组件共享一个状态对象，`SetRegs`/`SetMaps` 与 getters 访问 regs/maps；这些行无锁。但同一 Unwinder 对象的跨线程访问契约未建立，组件共享不等于线程并发。",
        "- **CoredumpThread / DfxProcess（CR-0157–0160）**：`CoredumpThread::Init` 设置 regs，DfxProcess setters/getters 暴露 keyThread_/regs_。已检查进程转储调用点；尚无同一个实例跨线程并发读写的证据。",
        "- `BUILD.gn` 将相关源列入 production-capable `ohos_shared_library`、unwinder 和 process-dump targets；这些目标不是 `testonly` fuzz target。构建声明不能证明所选产品镜像启用目标，也不能建立运行时可达性或调用并发。本次没有构建产品或运行 TSan。",
        "",
        "## 限制与下一步",
        "",
        "当前 11 个 CLI 文件均 parse complete，但范围只有 2,498 LOC，profile 为 light-ast；这不代表完整组件语义覆盖。最值得继续取证的是 LocalThreadContextMix singleton 的产品服务序列化与并发 dump 调用，以及 StackPrinter 实例是否会被并发重配/读取。缺这些证据前，不改 detector、不将零结果或候选数解释成 precision/recall、安全或漏洞确认。",
        "",
        "复验：`python research/evidence/cpp/t40_faultloggerd_sharedptr_audit_20261024.py` 生成逐 ID JSON；`python research/evidence/cpp/verify_t40_faultloggerd_sharedptr_audit_20261024.py` 校验来源身份、42 行映射、A0 状态和 CLI 报告。",
        "",
    ]
    REPORT.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} with {len(items)} A0 rows")


if __name__ == "__main__":
    main()
