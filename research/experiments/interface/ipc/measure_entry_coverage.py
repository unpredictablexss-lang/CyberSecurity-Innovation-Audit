"""Measure IPC entry discovery on real OpenHarmony components.

Answers one question only: which IPC entry points does the detector actually
reach, and where does it still fail to? It is the measurement behind
`docs/research/ipc_scanner_v0_2_entry_coverage_2026-10-10.md`.

Reports, per component, three things kept deliberately separate (the split the
corpus protocol asks for):

  1. run state      - how many units were read, how many parsed cleanly
  2. analysis coverage - dispatchers, dispatch bindings, entry roots, and the
                      same numbers for the legacy name allowlist it replaces
  3. root-cause intersection - whether the symbols recorded for the verified
                      historical pairs are among the discovered entries

Nothing here establishes a vulnerability, reachability or exploitability, and
`validated_vulnerability` stays 0. Generated artifacts belong outside Git.

Usage:
  .venv/bin/python research/experiments/interface/ipc/measure_entry_coverage.py \
      --corpus ~/openharmony-audit/perf-corpus \
      --json outputs/reports/entry_coverage.json \
      --md outputs/reports/entry_coverage.md
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

# Run from anywhere: the project root is four levels up from this file.
sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from src.ohscanner.detectors.interface.analysis import Interpreter
from src.ohscanner.detectors.interface.entry_index import EntryIndex
from src.ohscanner.detectors.interface.models import IpcPolicy

SOURCE_SUFFIXES = (".cpp", ".cc", ".cxx", ".c", ".h", ".hh", ".hpp", ".inl")
SKIPPED_DIRS = ("/test/", "/unittest/", "/fuzztest/")
DEFAULT_CORPUS = Path.home() / "openharmony-audit" / "perf-corpus"
SERVICE_DELEGATION = re.compile(r"([\w:<>]+)\s*::\s*GetInstance\s*\(\s*\)\s*->\s*(\w+)")


class Unit:
    """Minimal SourceUnit stand-in: the index reads exactly these four fields."""

    def __init__(self, path, text, language):
        self.path = path
        self.language = language
        self.text = text
        self.parse_status = "complete"


def load_units(component_dir):
    units = []
    for path in sorted(component_dir.rglob("*")):
        if path.suffix not in SOURCE_SUFFIXES or not path.is_file():
            continue
        relative = "/" + path.relative_to(component_dir).as_posix()
        if any(marker in relative for marker in SKIPPED_DIRS):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        units.append(Unit(relative.lstrip("/"), text, "c" if path.suffix == ".c" else "cpp"))
    return units


def git_head(component_dir):
    try:
        return subprocess.check_output(
            ["git", "-C", str(component_dir), "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL).decode().strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def delegated_targets(interpreter, units):
    """Service methods reachable one hop from a handler through a source-backed
    `Type::GetInstance()->Method` receiver and a unique definition.

    Counted separately from dispatch-bound entries: this is a call edge the
    interpreter follows, not an IPC entry point.
    """
    index = interpreter.index
    if index is None:
        return set()
    found = set()
    for unit in units:
        for receiver, method in SERVICE_DELEGATION.findall(unit.text):
            target = index.resolve_receiver(receiver + "::GetInstance()->" + method)
            if not target or "::" not in target:
                continue
            owner, name = target.rsplit("::", 1)
            matches = interpreter.functions_by_owner_name.get((owner.rsplit("::", 1)[-1], name), [])
            if len(matches) == 1:
                found.add(matches[0].qualified)
    return found


def measure_component(component_dir, policy):
    units = load_units(component_dir)
    index = EntryIndex(units, policy)
    counts = index.counts()
    interpreter = Interpreter(units, policy)
    with_index = interpreter._entry_roots()
    delegated = delegated_targets(interpreter, units)
    interpreter.index = None
    interpreter.functions_by_owner_name = {}
    legacy = interpreter._entry_roots()
    return {
        "component": component_dir.name,
        "commit": git_head(component_dir),
        "source_files": len(units),
        # Manifest digest of the file list, so a later run can prove it read the
        # same set. Per-file source hashes stay in the runner's own records.
        "manifest_sha256": hashlib.sha256(
            "\n".join(sorted(u.path for u in units)).encode()).hexdigest(),
        "partial_sources": sum(1 for item in index.limitations
                               if item.startswith("Partial source in entry index:")),
        "dispatchers": counts["dispatchers"],
        "dispatchers_with_guard": counts["dispatchers_with_guard"],
        "stub_classes": counts["stub_classes"],
        "entries": counts["entries"],
        "entries_by_evidence": counts["entries_by_evidence"],
        "entries_by_kind": counts["entries_by_kind"],
        "entries_under_conditional": sum(1 for e in index.entries if e.conditional),
        "bound_handlers": counts["bound_handlers"],
        "root_bindings": counts["root_bindings"],
        "unresolved_transactions": counts["unresolved_transactions"],
        "legacy_roots": len(legacy),
        "dispatch_roots": len(with_index),
        "delegated_targets": len(delegated),
        "index_limitations": counts["limitations"],
        "_source_reachable": sorted(
            {entry.handler for entry in index.entries if entry.handler_bound and entry.handler}
            | {entry.dispatcher for entry in index.entries}
            | delegated),
        "_legacy_reachable": sorted(
            {function.qualified for function, _grade, _note in legacy}),
    }


def _symbol_key(qualified):
    """`A::B::Class::Method` -> `Class::Method`.

    Namespace-tolerant but class-exact: comparing on the method name alone makes a
    method of an unrelated class look like the same symbol, which would overstate
    coverage.
    """
    parts = qualified.split("::")
    return "::".join(parts[-2:]) if len(parts) >= 2 else qualified


def discovery_check(pairs_path, measured):
    """Whether the symbols recorded for the verified pairs are reached at all.

    "Reached" means one of: a dispatch-bound handler, a dispatcher, an admitted
    entry root, or a service method one hop away through a source-backed
    `GetInstance()` receiver. It is a coverage statement, never a vulnerability
    verdict: nothing here says the symbol is reachable by an attacker.
    """
    if not pairs_path.exists():
        return {"available": False, "reason": "verified pair manifest not found: " + str(pairs_path)}
    by_repo = {row["component"]: row for row in measured}
    records = []
    for line in pairs_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        sample = json.loads(line)
        component = sample["repository"].split("/")[-1]
        row = by_repo.get(component)
        source = {_symbol_key(item) for item in row["_source_reachable"]} if row else set()
        legacy = {_symbol_key(item) for item in row["_legacy_reachable"]} if row else set()
        for symbol in sample.get("affected_symbols", ()):
            key = _symbol_key(symbol)
            if row is None:
                verdict, note = "not_in_corpus", "component not in corpus"
            elif key in source:
                verdict, note = "source_derived", ""
            elif key in legacy:
                verdict, note = "legacy_allowlist_only", (
                    "reached only because models.py names it explicitly; no source-derived "
                    "dispatch binding in this repository")
            else:
                verdict, note = "not_reached", (
                    "not a dispatcher, dispatch-bound handler, admitted root or "
                    "one-hop service method in this repository")
            records.append({
                "sample_id": sample["sample_id"],
                "repository": sample["repository"],
                "affected_symbol": symbol,
                "component_in_corpus": row is not None,
                "reached": verdict in ("source_derived", "legacy_allowlist_only"),
                "verdict": verdict,
                "note": note,
            })
    return {
        "available": True,
        "records": records,
        "total": len(records),
        "source_derived": sum(1 for r in records if r["verdict"] == "source_derived"),
        "legacy_allowlist_only": sum(1 for r in records if r["verdict"] == "legacy_allowlist_only"),
        "not_reached": sum(1 for r in records if r["verdict"] == "not_reached"),
    }


def render_markdown(document):
    lines = ["# IPC 入口覆盖实测（v0.2）", "",
             "> 由 `research/experiments/interface/ipc/measure_entry_coverage.py` 生成。",
             "> 只回答「检测器实际够到哪些入口、还差在哪」，不构成漏洞、可达性或可利用性结论；",
             "> `validated_vulnerability` 恒为 0。", "",
             "## 1. 运行状态", ""]
    lines += ["| 组件 | 固定提交 | 源文件 | 索引内 partial |", "|---|---|---:|---:|"]
    for row in document["components"]:
        lines.append(f"| {row['component']} | `{row['commit'][:12]}` | {row['source_files']} | "
                     f"{row['partial_sources']} |")
    totals = document["totals"]
    lines += [f"| **合计** | | **{totals['source_files']}** | **{totals['partial_sources']}** |", "",
              "## 2. 分析覆盖（入口发现）", "",
              "「旧谓词」是 v0.1 的硬编码名字白名单（`OnRemoteRequest` / `*Inner` in `*Stub` / "
              "`models.py` 里手写的 `service_entries`）；「源码分发 root」是本次新增的源码派生入口。",
              "两者用**同一个** root 收集函数测出，只有索引开关不同，因此可比。", "",
              "| 组件 | dispatcher（按签名） | 分发绑定 | 源码分发 root | 旧谓词 root | 未解析事务 | 证据分布 |",
              "|---|---:|---:|---:|---:|---:|---|"]
    for row in document["components"]:
        evidence = "、".join(f"{k}:{v}" for k, v in sorted(row["entries_by_evidence"].items())) or "—"
        lines.append(f"| {row['component']} | {row['dispatchers']} | {row['bound_handlers']} | "
                     f"{row['dispatch_roots']} | {row['legacy_roots']} | "
                     f"{row['unresolved_transactions']} | {evidence} |")
    lines += [f"| **合计** | **{totals['dispatchers']}** | **{totals['bound_handlers']}** | "
              f"**{totals['dispatch_roots']}** | **{totals['legacy_roots']}** | "
              f"**{totals['unresolved_transactions']}** | |", "",
              "分发形状分布：",
              ""]
    for key, value in sorted(document["kinds"].items()):
        lines.append(f"- `{key}`：{value}")
    labels = {"source_derived": "源码派生",
              "legacy_allowlist_only": "**仅靠硬编码白名单**",
              "not_reached": "**未触达**",
              "not_in_corpus": "语料外"}
    lines += ["", "## 3. 根因相交：历史 S2 样本的符号是否被触达", "",
              "「触达」的判据：该符号是 dispatcher、是 dispatch 绑定的 handler、是被采纳的入口 root，"
              "或是由源码可证的 `GetInstance()` 接收者一跳可达的服务方法。"
              "比对为**类名精确**（`Class::Method`，允许命名空间前缀），只看方法名会把无关类误判为同一符号。",
              "**这是覆盖陈述，不是可利用性结论。**", "",
              "### 3.1 历史修订（验收口径）", "",
              "记录符号来自各样本的 vulnerable/fixed 修订，因此只有按**历史修订**建索引才是正确的验收。", ""]
    history = document["discovery_history"]
    if not history.get("available"):
        lines.append("不可用：" + history.get("reason", "unknown"))
    else:
        lines += [f"共 {history['total']} 条「样本 × 修订」记录：源码派生 **{history['source_derived']}**、"
                  f"仅靠硬编码白名单 **{history['legacy_allowlist_only']}**、"
                  f"未触达 **{history['not_reached']}**。", "",
                  "| 样本 | 修订 | 记录符号 | 读取文件 | 判定 |",
                  "|---|---|---|---:|---|"]
        for record in history["records"]:
            lines.append(f"| {record['sample_id']} | {record['revision']} | "
                         f"`{record['affected_symbol']}` | {record['files_scanned']} | "
                         f"{labels[record['verdict']]} |")
    lines += ["", "### 3.2 当代 HEAD（参考，不是验收口径）", "",
              "历史符号不保证仍存在于组件现行代码；此节用于观察「符号是否还在 HEAD 里」，"
              "不作为检测器覆盖的判据。", ""]
    check = document["discovery_head"]
    if not check.get("available"):
        lines.append("不可用：" + check.get("reason", "unknown"))
    else:
        lines += [f"共 {check['total']} 条记录符号：源码派生 **{check['source_derived']}**、"
                  f"仅靠硬编码白名单 **{check['legacy_allowlist_only']}**、"
                  f"未触达 **{check['not_reached']}**。", "",
                  "| 样本 | 仓库 | 记录符号 | 判定 | 备注 |",
                  "|---|---|---|---|---|"]
        for record in check["records"]:
            lines.append(f"| {record['sample_id']} | {record['repository'].split('/')[-1]} | "
                         f"`{record['affected_symbol']}` | {labels[record['verdict']]} | "
                         f"{record['note']} |")
    lines += ["", "## 4. 限制", "",
              "- 入口被找到**不等于**可达：`IPCObjectStub::SendRequest` 里 `GET_PID_UID` 一类分支位于 "
              "`#ifndef CONFIG_IPC_SINGLE` 之内，本报告只记录条件上下文，不判定其在某个构建下可达。",
              "- 分发器级 guard（如 `IsCallerValid`、`IsPermissionGranted(code)`）不在 `IpcPolicy` 内，"
              "含此类 guard 的入口在检测器输出中被归为 AUTH-04（覆盖未证明）而非 AUTH-02（缺授权）。",
              "- 索引只做私有语法重建与名字/形状匹配，没有宏展开、重载解析或虚调用证明。",
              "- 本脚本读的是工作副本目录而非固定 Git 对象；固定提交号记在上表，用 `git rev-parse` 复核。",
              "- 「索引内 partial」是私有解析视角，不等于队长 Runner 的 `source_parsing` 覆盖。", ""]
    return "\n".join(lines) + "\n"


def historical_discovery(pairs_root, pairs_path, policy):
    """Whether the recorded symbol is reached in the *historical* revision.

    This is the acceptance check that matters: the symbols in `verified_pairs.jsonl`
    come from the vulnerable and fixed revisions recorded for each sample, not from
    the contemporary HEAD of the component repositories. Comparing them against HEAD
    reports "not reached" for code that has since been rewritten (and vice versa),
    which says nothing about detector coverage.

    Caveat: a pair directory holds only the files the patch touched, so the index
    sees a truncated view and cross-file edges may be missing.
    """
    if not pairs_path.exists() or not pairs_root.is_dir():
        return {"available": False, "reason": "verified pairs or pair sources not available"}
    records = []
    for line in pairs_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        sample = json.loads(line)
        for revision in ("vulnerable", "fixed"):
            files = [item for item in sample.get("source_files", ())
                     if item.get("revision") == revision]
            units = []
            for item in files:
                path = pairs_root / sample["sample_id"] / revision / item["path"]
                if not path.is_file():
                    continue
                try:
                    text = path.read_text(encoding="utf-8")
                except (UnicodeDecodeError, OSError):
                    continue
                units.append(Unit(item["path"], text,
                                  "c" if item["path"].endswith(".c") else "cpp"))
            if not units:
                continue
            index = EntryIndex(units, policy)
            interpreter = Interpreter(units, policy)
            with_index = interpreter._entry_roots()
            source = {_symbol_key(entry.handler) for entry in index.entries if entry.handler_bound
                      and entry.handler}
            source |= {_symbol_key(entry.dispatcher) for entry in index.entries}
            source |= {_symbol_key(target) for target in delegated_targets(interpreter, units)}
            legacy = {_symbol_key(function.qualified) for function, _g, _n in with_index
                      if _g == "allowlist"}
            for symbol in sample.get("affected_symbols", ()):
                key = _symbol_key(symbol)
                if key in source:
                    verdict = "source_derived"
                elif key in legacy:
                    verdict = "legacy_allowlist_only"
                else:
                    verdict = "not_reached"
                records.append({
                    "sample_id": sample["sample_id"], "revision": revision,
                    "affected_symbol": symbol, "files_scanned": len(units),
                    "verdict": verdict,
                })
    return {
        "available": True, "records": records, "total": len(records),
        "source_derived": sum(1 for r in records if r["verdict"] == "source_derived"),
        "legacy_allowlist_only": sum(1 for r in records if r["verdict"] == "legacy_allowlist_only"),
        "not_reached": sum(1 for r in records if r["verdict"] == "not_reached"),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--component", action="append", default=[])
    parser.add_argument("--json", type=Path, default=None)
    parser.add_argument("--md", type=Path, default=None)
    parser.add_argument("--pairs", type=Path, default=None)
    parser.add_argument("--pairs-root", type=Path,
                        default=Path.home() / "openharmony-audit" / "ipc-research" / "pairs")
    parser.add_argument("--skip-history", action="store_true",
                        help="skip the historical-revision symbol check")
    args = parser.parse_args()

    project = Path(__file__).resolve().parents[4]
    pairs = args.pairs or project / "research/corpus/interface/ipc/verified_pairs.jsonl"
    names = args.component or sorted(p.name for p in args.corpus.iterdir() if p.is_dir())
    policy = IpcPolicy()

    components = []
    for name in names:
        directory = args.corpus / name
        if not directory.is_dir():
            print("skipping missing component:", name, flush=True)
            continue
        row = measure_component(directory, policy)
        components.append(row)
        print(f"{row['component']:38s} files={row['source_files']:5d} "
              f"disp={row['dispatchers']:4d} bound={row['bound_handlers']:5d} "
              f"roots={row['dispatch_roots']:5d} legacy={row['legacy_roots']:4d} "
              f"unresolved={row['unresolved_transactions']:4d}", flush=True)

    kinds = Counter()
    totals = Counter()
    for row in components:
        kinds.update(row["entries_by_kind"])
        for key in ("source_files", "partial_sources", "dispatchers", "bound_handlers",
                    "dispatch_roots", "legacy_roots", "unresolved_transactions",
                    "entries_under_conditional", "stub_classes"):
            totals[key] += row[key]

    document = {
        "schema_version": 1,
        "experiment_kind": "ipc_entry_coverage_measurement",
        "corpus": str(args.corpus),
        "policy_model_version": "oh-ipc-2026.10-v1",
        "validated_vulnerability": 0,
        "components": [{k: v for k, v in row.items() if not k.startswith("_")}
                       for row in components],
        "totals": dict(totals),
        "kinds": dict(sorted(kinds.items())),
        "discovery_head": discovery_check(pairs, components),
        "discovery_history": ({"available": False, "reason": "skipped"}
                              if args.skip_history
                              else historical_discovery(args.pairs_root, pairs, policy)),
        "limitations": [
            "Entry discovery is not reachability: macro-conditional dispatch is recorded, not decided.",
            "Dispatcher-level guards are not modelled; such entries are classified AUTH-04, not suppressed.",
            "Private parser only: no macro expansion, overload resolution or virtual dispatch proof.",
            "The index reads a working copy; the pinned commit is recorded per component for review.",
        ],
    }

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n")
        print("wrote", args.json)
    if args.md:
        args.md.parent.mkdir(parents=True, exist_ok=True)
        args.md.write_text(render_markdown(document))
        print("wrote", args.md)


if __name__ == "__main__":
    main()
