#!/usr/bin/env python3
"""Scale/performance benchmark for the OHScanner pinned-Git execution path.

Runs the real `src.cli ohscan-run` entry point over a corpus of pinned
OpenHarmony component commits and measures, per component:

  * wall-clock seconds for the whole CLI process;
  * process CPU time and peak resident set size (RSS) when the platform exposes them;
  * in-tool source-read, AST parse, detector, and report-render stage times;
  * the tool's own reported scanned-file count and source bytes;
  * the pinned tree's C/C++ source-file count and line count;
  * parse coverage (complete/partial) and detector coverage (examined/unexamined).

Scope and honesty limits
------------------------
This benchmark measures *platform cost* — pinned Git object read + AST/fact
building + selected detector execution. The default detector is the explicitly
non-security example plugin `ohscanner.example.cpp.copy-calls`; callers may
select first-party detectors. It is **not** an accuracy measurement, and
candidate counts or completed coverage do not establish exploitability or
component safety.

The corpus is fixed by a manifest of full commit SHAs so the numbers are
reproducible. Reading is offline: the tool never fetches or checks out.

Usage
-----
    python scripts/perf_scale_scan.py \
        --manifest benchmarks/perf_scale_corpus_2026-10-10.json \
        --json-out outputs/reports/perf_scale_scan.json \
        --md-out benchmarks/组件性能规模实测.md
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import time

SRC_EXTS = (".cpp", ".cc", ".cxx", ".c", ".h", ".hpp", ".inl")
DETECTOR_ID = "ohscanner.example.cpp.copy-calls"


# Never let a measurement reach the network. GIT_NO_LAZY_FETCH needs Git >= 2.36;
# on older Git the shallow, non-promisor corpus clones have no remote to fetch
# from anyway, so both layers together keep the benchmark strictly offline.
GIT_ENV = {
    **os.environ,
    "GIT_NO_LAZY_FETCH": "1",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_ASKPASS": "/bin/true",
}


def git(repo_dir: str, *args: str) -> bytes:
    proc = subprocess.run(["git", "-C", repo_dir, *args],
                          capture_output=True, check=False, env=GIT_ENV)
    if proc.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed in {repo_dir}: "
            f"{proc.stderr.decode('utf-8', 'replace').strip()}"
        )
    return proc.stdout


def git_sources(repo_dir: str, commit: str) -> list[str]:
    """Repo-relative paths of every C/C++ source file in the pinned tree."""
    raw = git(repo_dir, "ls-tree", "-r", "-z", "--name-only", commit)
    return [n for n in raw.decode("utf-8", "replace").split("\0")
            if n.endswith(SRC_EXTS)]


def git_loc(repo_dir: str, commit: str, paths: list[str]) -> int:
    """Total line count of the given blobs, streamed through `git cat-file`."""
    if not paths:
        return 0
    payload = "".join(f"{commit}:{p}\n" for p in paths).encode()
    proc = subprocess.run(["git", "-C", repo_dir, "cat-file", "--batch"],
                          input=payload, capture_output=True, check=False, env=GIT_ENV)
    data = proc.stdout
    lines = i = 0
    while i < len(data):
        cut = data.find(b"\n", i)
        if cut < 0:
            break
        parts = data[i:cut].decode("utf-8", "replace").split()
        if len(parts) != 3 or parts[1] != "blob":
            break  # missing/promisor object: stop rather than guess
        size = int(parts[2])
        body = data[cut + 1:cut + 1 + size]
        lines += body.count(b"\n")
        i = cut + 1 + size + 1
    return lines


def run_measured(cmd: list[str], cwd: str, log_path: pathlib.Path):
    """Run cmd, returning (exit_code, wall_seconds, peak_rss_kb).

    The measurement is taken by a deliberately tiny helper process, not by this
    script. On Linux a forked child starts life sharing the parent's resident
    pages, so ``ru_maxrss`` of a short-lived child is floored by *the parent's*
    RSS at fork time. Measuring from this process (which buffers whole-file
    blobs while counting lines) would therefore report the parent's footprint
    instead of the scanner's. A minimal parent keeps that floor negligible.
    """
    helper = (
        "import json,subprocess,sys,time;"
        "cmd=json.loads(sys.argv[1]);log=sys.argv[2];"
        "t0=time.perf_counter();"
        "fh=open(log,'wb');"
        "p=subprocess.Popen(cmd,stdout=fh,stderr=subprocess.STDOUT);"
        "code=p.wait();"
        "elapsed=time.perf_counter()-t0;\n"
        "try:\n import resource\n ru=resource.getrusage(resource.RUSAGE_CHILDREN)\n peak=ru.ru_maxrss if sys.platform!='darwin' else ru.ru_maxrss/1024\n cpu=ru.ru_utime+ru.ru_stime\n"
        "except (ImportError,AttributeError,OSError): peak=None; cpu=None\n"
        "sys.stdout.write(json.dumps({'exit':code,'wall':elapsed,'peak_kb':peak,'cpu_seconds':cpu}))"
    )
    proc = subprocess.run(
        [sys.executable, "-c", helper, json.dumps(cmd), str(log_path)],
        cwd=cwd, capture_output=True, text=True, env=GIT_ENV, check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"measurement helper failed: {proc.stderr.strip()}")
    measured = json.loads(proc.stdout)
    return measured["exit"], measured["wall"], measured["peak_kb"], measured["cpu_seconds"]


def result_signature(report: dict) -> str:
    """Hash result identity, candidates, source locations, and coverage only."""
    stable_runs = []
    for run in report.get("detector_runs", []):
        stable_runs.append({key: run.get(key) for key in (
            "tool", "tool_version", "status", "scope_files", "scope_loc",
            "diagnostics", "limitations", "parsing")})
    stable = {key: report.get(key) for key in (
        "repository", "target_id", "commit", "git_tree", "snapshot_sha256",
        "provenance", "profile_id", "environment", "status", "scope",
        "source_parsing", "detector_count", "diagnostic_count",
        "detector_coverage", "files_in_scope_without_a_claiming_detector")}
    stable["detector_runs"] = stable_runs
    payload = json.dumps(stable, sort_keys=True, ensure_ascii=False,
                         separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def benchmark_one(project_root: str, python: str, entry: dict,
                  report_dir: pathlib.Path, targets_root: pathlib.Path,
                  ast_cache_dir: pathlib.Path | None = None,
                  detector_result_cache_dir: pathlib.Path | None = None,
                  detector_ids: tuple[str, ...] = (DETECTOR_ID,)) -> dict:
    """Run one manifest entry and return an aggregated measurement row.

    An entry may carry ``include`` — a list of repository-relative path
    prefixes. The scanner refuses a tree whose total source size exceeds its
    bounded scope, so a repository that is too large is measured as several
    shards (`--include`) and the shard results are summed. Shard counts are
    recorded so a sharded row is never mistaken for a single whole-tree run.
    """
    label = entry["label"]
    repo_dir = pathlib.Path(entry["repo_dir"])
    if not repo_dir.is_absolute():
        repo_dir = targets_root / repo_dir
    repo_dir, commit = str(repo_dir), entry["commit"]

    sources = git_sources(repo_dir, commit)
    loc = git_loc(repo_dir, commit, sources)

    shard_specs = entry.get("include") or [[]]
    shards = []
    for idx, prefixes in enumerate(shard_specs):
        sub_label = label if not prefixes else f"{label}__shard{idx:02d}"
        json_out = report_dir / f"{sub_label}.json"
        log_out = report_dir / f"{sub_label}.log"
        cmd = [
            python, "-m", "src.cli", "ohscan-run",
            "--repo-dir", repo_dir,
            "--repository", entry["repository"],
            "--commit", commit,
            "--json-out", str(json_out),
            "--md-out", str(report_dir / f"{sub_label}.md"),
        ]
        for detector_id in detector_ids:
            cmd += ["--detector", detector_id]
        if any(detector_id.startswith("ohscanner.example.") for detector_id in detector_ids):
            cmd.append("--allow-example-detectors")
        if entry.get("base_commit"):
            cmd += ["--base-commit", entry["base_commit"]]
        # Keep cache size accounting local to one immutable benchmark shard.
        # Each CLI process enforces a bounded directory by enumerating its
        # entries at startup; sharing one corpus-wide directory would repeat
        # an ever-growing stat walk for every component and shard.
        shard_ast_cache_dir = (
            ast_cache_dir / label / sub_label if ast_cache_dir is not None else None
        )
        shard_result_cache_dir = (
            detector_result_cache_dir / label / sub_label
            if detector_result_cache_dir is not None else None
        )
        for prefix in prefixes:
            cmd += ["--include", prefix]
        if shard_ast_cache_dir is not None:
            cmd += ["--ast-cache-dir", str(shard_ast_cache_dir)]
        if shard_result_cache_dir is not None:
            cmd += ["--detector-result-cache-dir", str(shard_result_cache_dir)]
        code, elapsed, peak_kb, cpu_seconds = run_measured(cmd, project_root, log_out)
        shards.append({"include": prefixes, "exit": code, "wall": elapsed,
                       "peak_kb": peak_kb, "cpu_seconds": cpu_seconds,
                       "json": json_out, "log": log_out})

    failed = [s for s in shards if s["exit"] != 0]
    row = {
        "label": label,
        "repository": entry["repository"],
        "commit": commit,
        "commit_date": entry.get("commit_date"),
        "exit_code": failed[0]["exit"] if failed else 0,
        "failed_shards": len(failed),
        "shards": len(shard_specs),
        "wall_seconds": round(sum(s["wall"] for s in shards), 4),
        "peak_rss_kb": max((s["peak_kb"] for s in shards if s["peak_kb"] is not None), default=None),
        "cpu_seconds": sum(s["cpu_seconds"] for s in shards
                            if s["cpu_seconds"] is not None),
        "tree_source_files": len(sources),
        "tree_source_loc": loc,
        "report_path": str(shards[0]["json"]),
    }

    if failed:
        row["error"] = failed[0]["log"].read_text(
            encoding="utf-8", errors="replace")[-800:]
        return row

    totals = {"scanned_files": 0, "scanned_bytes": 0, "parse_complete": 0,
              "parse_partial": 0, "analyzed_files": 0, "unexamined_files": 0,
              "diagnostic_count": 0}
    statuses = []
    phase_keys = (
        "source_read_seconds", "source_read_cpu_seconds", "ast_parse_seconds",
        "ast_cache_setup_seconds", "ast_cache_setup_cpu_seconds",
        "ast_parse_cpu_seconds", "frontend_seconds", "frontend_cpu_seconds",
        "facts_build_seconds", "facts_build_cpu_seconds",
        "detector_execution_seconds", "detector_stage_wall_seconds",
        "detector_stage_cpu_seconds", "report_build_seconds",
        "report_build_cpu_seconds", "report_render_seconds",
        "report_render_cpu_seconds", "report_json_serialization_seconds",
        "report_file_write_seconds",
        "parse_files", "indexed_files",
    )
    phase_totals = {key: 0.0 for key in phase_keys}
    phase_totals["source_read_child_cpu_seconds"] = 0.0
    child_cpu_known = True
    cache_keys = ("hits", "misses", "bypassed", "invalid", "writes",
                  "evictions", "oversize_not_stored", "cleared_entries",
                  "cleared_bytes", "cleanup_errors")
    cache_totals = {key: 0 for key in cache_keys}
    cache_bytes_values = []
    cache_limit_values = []
    detector_cache_keys = ("hits", "misses", "bypassed", "invalid", "writes",
                           "write_skipped", "read_errors")
    detector_cache_totals = {key: 0 for key in detector_cache_keys}
    detector_cache_hit_paths = set()
    cpu_quota_values = []
    cpu_quota_statuses = []
    detector_statuses = []
    for shard in shards:
        report = json.loads(shard["json"].read_text(encoding="utf-8"))
        shard["result_signature"] = result_signature(report)
        environment = report.get("environment", {})
        cpu_quota_values.append(environment.get("cpu_quota_cores"))
        cpu_quota_statuses.append(environment.get("cpu_quota_status", "unknown"))
        perf = report.get("performance", {})
        for key in phase_keys:
            phase_totals[key] += perf.get(key, 0) or 0
        child_cpu = perf.get("source_read_child_cpu_seconds")
        if child_cpu is None:
            child_cpu_known = False
        else:
            phase_totals["source_read_child_cpu_seconds"] += child_cpu
        cache = perf.get("ast_cache", {})
        for key in cache_keys:
            cache_totals[key] += cache.get(key, 0) or 0
        if cache.get("cache_bytes") is not None:
            cache_bytes_values.append(cache["cache_bytes"])
        if cache.get("max_bytes") is not None:
            cache_limit_values.append(cache["max_bytes"])
        detector_cache = perf.get("detector_result_cache", {})
        for key in detector_cache_keys:
            detector_cache_totals[key] += detector_cache.get(key, 0) or 0
        detector_cache_hit_paths.update(detector_cache.get("hit_paths", ()))
        scope = report.get("scope", {})
        parsing = report.get("source_parsing", {}).get("parsing_status", {})
        detector_coverages = report.get("detector_coverage", {}).get("detectors", {})
        covs = [detector_coverages.get(detector_id, {}) for detector_id in detector_ids]
        analyzed_paths = {path for cov in covs for path in cov.get("analyzed_files", [])}
        analyzed = len(analyzed_paths)
        totals["scanned_files"] += scope.get("selected_source_files", 0)
        totals["scanned_bytes"] += scope.get("selected_source_bytes", 0)
        totals["parse_complete"] += parsing.get("complete", 0)
        totals["parse_partial"] += parsing.get("partial", 0)
        totals["analyzed_files"] += analyzed
        totals["unexamined_files"] += sum(
            max(cov.get("applicable_files", 0) - len(cov.get("analyzed_files", [])), 0)
            for cov in covs)
        totals["diagnostic_count"] += report.get("diagnostic_count", 0) or 0
        statuses.append(report.get("status"))
        detector_statuses.extend(cov.get("status", "unknown") for cov in covs)

    row.update(totals)
    row.update(phase_totals)
    if not child_cpu_known:
        row["source_read_child_cpu_seconds"] = None
    row.update({f"ast_cache_{key}": value for key, value in cache_totals.items()})
    row["ast_cache_bytes"] = max(cache_bytes_values, default=None)
    row["ast_cache_max_bytes"] = max(cache_limit_values, default=None)
    row.update({f"detector_result_cache_{key}": value
                for key, value in detector_cache_totals.items()})
    row["detector_result_cache_reused_source_paths"] = len(detector_cache_hit_paths)
    lookups = cache_totals["hits"] + cache_totals["misses"] + cache_totals["invalid"]
    row["ast_cache_hit_rate"] = cache_totals["hits"] / lookups if lookups else None
    row["result_signature"] = hashlib.sha256(
        "".join(shard["result_signature"] for shard in shards).encode("ascii")
    ).hexdigest()
    row["peak_rss_status"] = "unknown" if row["peak_rss_kb"] is None else "resource.getrusage"
    row["cpu_status"] = "unknown" if row["cpu_seconds"] == 0 else "resource.getrusage"
    known_quotas = {value for value in cpu_quota_values if value is not None}
    row["cpu_quota_cores"] = (next(iter(known_quotas))
                               if len(known_quotas) == 1 else None)
    row["cpu_quota_status"] = (
        cpu_quota_statuses[0] if len(set(cpu_quota_statuses)) == 1 else "mixed"
    )
    row["average_cpu_quota_utilization"] = (
        row["cpu_seconds"] / (row["wall_seconds"] * row["cpu_quota_cores"])
        if row["cpu_quota_status"] == "limited" and row["cpu_quota_cores"]
        and row["wall_seconds"] and row["cpu_status"] != "unknown" else None
    )
    row["status"] = statuses[0] if len(set(statuses)) == 1 else "mixed"
    row["detector_status"] = (
        "partial" if any(value not in ("complete", "completed") for value in detector_statuses)
        else "complete")
    row["detector_ids"] = list(detector_ids)
    row["validated_vulnerability"] = 0
    row["files_per_second"] = (round(totals["scanned_files"] / row["wall_seconds"], 1)
                               if row["wall_seconds"] else None)
    row["mb_per_second"] = (round(totals["scanned_bytes"] / 1e6 / row["wall_seconds"], 2)
                            if row["wall_seconds"] else None)
    return row


def render_markdown(rows: list[dict], manifest_path: str) -> str:
    ok = [r for r in rows if r.get("exit_code") == 0]
    total_s = sum(r["wall_seconds"] for r in ok)
    total_files = sum(r.get("scanned_files", 0) for r in ok)
    total_bytes = sum(r.get("scanned_bytes", 0) for r in ok)
    total_loc = sum(r["tree_source_loc"] for r in ok)
    peak_values = [r["peak_rss_kb"] for r in ok if r.get("peak_rss_kb") is not None]
    peak = max(peak_values, default=None)

    out = [
        "# OHScanner 组件级性能与规模实测",
        "",
        "> 由 `scripts/perf_scale_scan.py` 生成。语料清单见 "
        f"`{manifest_path}`（固定完整 commit SHA，可复现）。",
        "> 测量固定 Git 对象读取、AST/事实构建和所选检测器运行成本；结果不是准确率或产品安全结论。",
        f"> 使用检测器：`{', '.join(rows[0].get('detector_ids', [DETECTOR_ID]))}`。",
        "> **这不是漏洞检出能力评测**；候选和 `completed` 状态均不证明漏洞或安全。",
        "",
        "## 汇总",
        "",
        f"- 组件数：**{len(ok)}**（共 {len(rows)} 条清单，失败 "
        f"{len(rows) - len(ok)}）",
        f"- 扫描源文件：**{total_files:,}**",
        f"- 扫描源码字节：**{total_bytes:,}**",
        f"- 语料 C/C++ 总行数（全部源文件，非扫描子集）：**{total_loc:,}**",
        f"- 累计墙钟：**{total_s:.2f} s**（单进程串行执行）",
        f"- 单次进程峰值 RSS 上界：**{peak / 1024:.1f} MB**" if peak is not None
        else "- 单次进程峰值 RSS 上界：**unknown**（当前平台没有可用的 resource.getrusage）",
        f"- CPU 时间合计：**{sum(r['cpu_seconds'] for r in ok):.2f} s**" if all(r.get("cpu_status") != "unknown" for r in ok)
        else "- CPU 时间合计：**unknown**",
        "- cgroup CPU 配额与平均配额利用率见逐组件 JSON；unknown 表示当前环境未暴露可验证限额，未用逻辑 CPU 数替代。平均利用率使用进程 CPU 核秒 /（墙钟 × 限额核数），不是瞬时系统 CPU 百分比。",
        "- 阶段时间和解析/缓存计数见逐组件性能 JSON；计时不改变扫描覆盖状态。",
        f"- 缓存命中：**{sum(r.get('ast_cache_hits', 0) for r in ok)}**；实际重新解析：**{sum(r.get('parse_files', 0) for r in ok)}**。",
        f"- AST 缓存 hit rate：**{sum(r.get('ast_cache_hits', 0) for r in ok) / max(1, sum(r.get('ast_cache_hits', 0) + r.get('ast_cache_misses', 0) + r.get('ast_cache_invalid', 0) for r in ok)):.1%}**；缓存容量与实际字节数见逐组件 JSON。",
        f"- Opt-in source-only detector result cache hit/miss：**{sum(r.get('detector_result_cache_hits', 0) for r in ok)} / {sum(r.get('detector_result_cache_misses', 0) for r in ok)}**；该计数不表示增量覆盖，未启用时为 0/0。",
        "- 解析/前端、事实构建、检测器、报告阶段 CPU 计时以及源码读取子进程 CPU（平台支持时）见逐组件 JSON；unknown 表示平台未提供可靠读数。",
        f"- 平均吞吐：**{total_files / total_s:.0f} files/s**、"
        f"**{total_bytes / 1e6 / total_s:.2f} MB/s**",
        f"- 分片测量的组件：**{sum(1 for r in ok if r.get('shards', 1) > 1)}**"
        "（整树超出 `M1 bounded scope`，按顶层目录分片）",
        "",
        "## 逐组件明细",
        "",
        "| 组件 | 固定提交 | 分片 | 扫描文件 | 扫描字节 | 树内 C/C++ 行 | 墙钟 (s) "
        "| 峰值 RSS (MB) | files/s | parse 完整/部分 | 检测器 |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---|---|",
    ]
    for r in rows:
        if r.get("exit_code") != 0:
            out.append(
                f"| {r['label']} | `{r['commit'][:12]}` | {r.get('shards', 1)} | — | — | "
                f"{r['tree_source_loc']:,} | — | — | — | **FAILED** "
                f"(exit {r['exit_code']}) | — |"
            )
            continue
        peak_text = (f"{r['peak_rss_kb'] / 1024:.1f}"
                     if r.get("peak_rss_kb") is not None else "unknown")
        out.append(
            f"| {r['label']} | `{r['commit'][:12]}` | {r.get('shards', 1)} | "
            f"{r['scanned_files']:,} | "
            f"{r['scanned_bytes']:,} | {r['tree_source_loc']:,} | "
            f"{r['wall_seconds']:.2f} | {peak_text} | "
        )
        # Keep stage data out of the compact legacy table; it is available in JSON.
        out[-1] += (f"{r['files_per_second']:.0f} | "
                    f"{r['parse_complete']}/{r['parse_partial']} | "
                    f"{r['detector_status']} |")

    out += [
        "",
        "## 语料构建与复现",
        "",
        "语料由 manifest 中的完整 commit SHA 固定。此脚本不会 clone/fetch，也不会切换目标仓库；"
        "运行前必须确认目标目录的 commit 与所需 blobs 已在本地，否则扫描失败，不会自动联网补取：",
        "",
        "```bash",
        "git -C <targets-root>/<repo_dir> cat-file -e <full-sha>^{commit}",
        "git -C <targets-root>/<repo_dir> rev-parse <full-sha>^{tree}",
        "```",
        "",
        f"11 条组件与其完整 SHA 记录在 `{manifest_path}`。一键复跑：",
        "",
        "```bash",
        "python scripts/perf_scale_scan.py \\",
        f"  --manifest {manifest_path} \\",
        "  --json-out outputs/reports/perf_scale_scan.json \\",
        "  --md-out benchmarks/组件性能规模实测.md",
        "```",
        "",
        "测量方式：每个组件在独立子进程中执行 `python -m src.cli ohscan-run`，由一个**最小的**"
        "父进程记录墙钟与 `ru_maxrss`。用最小父进程是必要的——Linux 上 fork 出的子进程在 exec 前"
        "共享父进程的常驻页，若从本脚本（它在统计行数时会缓冲整份源码）直接测量，得到的会是父进程"
        "的内存而不是扫描器的内存。CPU 与 RSS 来自平台支持时的 `resource.getrusage`；不可用时记为 unknown。",
        "",
        "## 限制",
        "",
        "- 语料是**组件级**（单次约 0.2k–2k 源文件），不是 OpenHarmony 千万行整树；"
        "整树规模需另行测量。",
        "- 执行是**同进程串行**的；轻量缓存仅覆盖固定 Git Blob 的 C/C++ 共享 AST 大纲，不覆盖检测器专用解析、跨文件 facts 或编译语义；硬超时/资源隔离仍未实现。",
        "- `-partial` 解析文件计入未分析（`unexamined`），因为当前无宏展开与完整 "
        "include 上下文。",
        "- 峰值 RSS 为单个 CLI 进程的 `ru_maxrss`；未测多进程并发下的总内存。",
        "- 分片组件的墙钟是各分片之和，含每片一次 Python 启动与 JSON 写出的固定开销，"
        "因此其 files/s 会低于同等规模的单次扫描，不能与单次运行的组件直接比吞吐。",
        "- `window_window_manager` 整树的源文件总量超过 `M1 bounded scope` 上限而无法"
        "单次扫描；这是当前实现的真实边界，分片是绕过方式而非其消失。",
        "- 上述耗时包含 Python 解释器启动与 JSON 报告写出，属于端到端口径。",
        "",
    ]
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    here = pathlib.Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--manifest", required=True,
                    help="JSON corpus manifest with full commit SHAs")
    ap.add_argument("--project-root", default=str(here),
                    help="OHScanner project root (default: script's repo)")
    ap.add_argument("--python", default=sys.executable,
                    help="interpreter used to run the CLI")
    ap.add_argument("--targets-root", default=str(pathlib.Path.home()),
                    help="root used to resolve relative repo_dir entries in the manifest")
    ap.add_argument("--ast-cache-dir", type=pathlib.Path, default=None,
                    help="optional persistent cache directory; reuse the same path for a hot-cache run")
    ap.add_argument("--detector-result-cache-dir", type=pathlib.Path, default=None,
                    help="optional source-Blob-only result cache; reuse the same path for a hot run")
    ap.add_argument("--detector", dest="detector_ids", nargs="+", default=[DETECTOR_ID],
                    help="detectors to execute; defaults to the non-security example detector")
    ap.add_argument("--compare-json", default=None,
                    help="compare normalized result and coverage identity with a prior performance run")
    ap.add_argument("--json-out", required=True)
    ap.add_argument("--md-out", required=True)
    ap.add_argument("--only", nargs="*",
                    help="restrict to these manifest labels")
    args = ap.parse_args(argv)

    manifest = json.loads(pathlib.Path(args.manifest).read_text(encoding="utf-8"))
    entries = manifest["entries"]
    if args.only:
        entries = [e for e in entries if e["label"] in set(args.only)]

    json_path = pathlib.Path(args.json_out).resolve()
    report_dir = json_path.parent / (json_path.stem + "_components")
    report_dir.mkdir(parents=True, exist_ok=True)

    rows = []
    for entry in entries:
        print(f"[run] {entry['label']} @ {entry['commit'][:12]} ...", flush=True)
        row = benchmark_one(args.project_root, args.python, entry, report_dir,
                            pathlib.Path(args.targets_root), args.ast_cache_dir,
                            args.detector_result_cache_dir, tuple(args.detector_ids))
        state = "ok" if row.get("exit_code") == 0 else f"FAIL({row['exit_code']})"
        peak_text = (f"{row['peak_rss_kb'] / 1024:.1f} MB"
                     if row.get("peak_rss_kb") is not None else "RSS unknown")
        print(f"      {state}  {row['wall_seconds']}s  "
              f"{peak_text}  "
              f"{row.get('scanned_files', '-')} files", flush=True)
        rows.append(row)

    json_path.parent.mkdir(parents=True, exist_ok=True)
    comparison = None
    if args.compare_json:
        previous = json.loads(pathlib.Path(args.compare_json).read_text(encoding="utf-8"))
        old_rows = {row["label"]: row for row in previous.get("rows", [])}
        mismatches = [
            row["label"] for row in rows
            if row["label"] not in old_rows
            or row.get("exit_code") != old_rows[row["label"]].get("exit_code")
            or row.get("result_signature") != old_rows[row["label"]].get("result_signature")
        ]
        comparison = {"compared_with": str(pathlib.Path(args.compare_json)),
                      "identical": not mismatches and len(old_rows) == len(rows),
                      "components": len(rows), "mismatches": mismatches}
    json_path.write_text(json.dumps({"manifest": args.manifest, "rows": rows,
                                     "comparison": comparison},
                                    indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    pathlib.Path(args.md_out).write_text(
        render_markdown(rows, args.manifest), encoding="utf-8")
    print(f"\nwrote {json_path}\nwrote {args.md_out}")
    return 0 if all(r.get("exit_code") == 0 for r in rows) and (comparison is None or comparison["identical"]) else 1


if __name__ == "__main__":
    sys.exit(main())
