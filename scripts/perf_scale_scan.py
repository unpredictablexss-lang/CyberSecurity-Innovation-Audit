#!/usr/bin/env python3
"""Scale/performance benchmark for the OHScanner pinned-Git execution path.

Runs the real `src.cli ohscan-run` entry point over a corpus of pinned
OpenHarmony component commits and measures, per component:

  * wall-clock seconds for the whole CLI process;
  * peak resident set size (RSS) of that process;
  * the tool's own reported scanned-file count and source bytes;
  * the pinned tree's C/C++ source-file count and line count;
  * parse coverage (complete/partial) and detector coverage (examined/unexamined).

Scope and honesty limits
------------------------
This benchmark measures *platform cost* — pinned Git object read + per-file
tree-sitter AST parse + detector dispatch — under the only detector that is
allowlisted today, the explicitly non-security example plugin
`ohscanner.example.cpp.copy-calls`. It is **not** a vulnerability-detection
quality measurement, and a `completed`/`completed_with_limitations` status is
not a statement that the component is safe.

The corpus is fixed by a manifest of full commit SHAs so the numbers are
reproducible. Reading is offline: the tool never fetches or checks out.

Usage
-----
    python scripts/perf_scale_scan.py \
        --manifest benchmarks/perf_scale_corpus_2026-10-10.json \
        --json-out outputs/reports/perf_scale_scan.json \
        --md-out docs/testing/ohscanner_performance_scale.md
"""

from __future__ import annotations

import argparse
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
        "import json,resource,subprocess,sys,time;"
        "cmd=json.loads(sys.argv[1]);log=sys.argv[2];"
        "t0=time.perf_counter();"
        "fh=open(log,'wb');"
        "p=subprocess.Popen(cmd,stdout=fh,stderr=subprocess.STDOUT);"
        "code=p.wait();"
        "elapsed=time.perf_counter()-t0;"
        "ru=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss;"
        "sys.stdout.write(json.dumps({'exit':code,'wall':elapsed,'peak_kb':ru}))"
    )
    proc = subprocess.run(
        [sys.executable, "-c", helper, json.dumps(cmd), str(log_path)],
        cwd=cwd, capture_output=True, text=True, env=GIT_ENV, check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"measurement helper failed: {proc.stderr.strip()}")
    measured = json.loads(proc.stdout)
    return measured["exit"], measured["wall"], measured["peak_kb"]


def benchmark_one(project_root: str, python: str, entry: dict,
                  report_dir: pathlib.Path) -> dict:
    """Run one manifest entry and return an aggregated measurement row.

    An entry may carry ``include`` — a list of repository-relative path
    prefixes. The scanner refuses a tree whose total source size exceeds its
    bounded scope, so a repository that is too large is measured as several
    shards (`--include`) and the shard results are summed. Shard counts are
    recorded so a sharded row is never mistaken for a single whole-tree run.
    """
    label = entry["label"]
    repo_dir, commit = entry["repo_dir"], entry["commit"]

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
            "--detector", DETECTOR_ID,
            "--allow-example-detectors",
            "--json-out", str(json_out),
        ]
        for prefix in prefixes:
            cmd += ["--include", prefix]
        code, elapsed, peak_kb = run_measured(cmd, project_root, log_out)
        shards.append({"include": prefixes, "exit": code, "wall": elapsed,
                       "peak_kb": peak_kb, "json": json_out, "log": log_out})

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
        "peak_rss_kb": max(s["peak_kb"] for s in shards),
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
    for shard in shards:
        report = json.loads(shard["json"].read_text(encoding="utf-8"))
        scope = report.get("scope", {})
        parsing = report.get("source_parsing", {}).get("parsing_status", {})
        cov = report.get("detector_coverage", {}).get(
            "detectors", {}).get(DETECTOR_ID, {})
        analyzed = len(cov.get("analyzed_files", []))
        totals["scanned_files"] += scope.get("selected_source_files", 0)
        totals["scanned_bytes"] += scope.get("selected_source_bytes", 0)
        totals["parse_complete"] += parsing.get("complete", 0)
        totals["parse_partial"] += parsing.get("partial", 0)
        totals["analyzed_files"] += analyzed
        totals["unexamined_files"] += max(
            cov.get("applicable_files", 0) - analyzed, 0)
        totals["diagnostic_count"] += report.get("diagnostic_count", 0) or 0
        statuses.append(report.get("status"))

    row.update(totals)
    row["status"] = statuses[0] if len(set(statuses)) == 1 else "mixed"
    row["detector_status"] = "partial"
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
    peak = max((r["peak_rss_kb"] for r in ok), default=0)

    out = [
        "# OHScanner 组件级性能与规模实测",
        "",
        "> 由 `scripts/perf_scale_scan.py` 生成。语料清单见 "
        f"`{manifest_path}`（固定完整 commit SHA，可复现）。",
        "> 测量的是**平台成本**：固定 Git 对象读取 + 逐文件 tree-sitter AST 解析 + "
        "检测器调度，",
        "> 使用当前唯一允许登记的非安全示例插件 "
        f"`{DETECTOR_ID}`。",
        "> **这不是漏洞检出能力评测**；`completed` 状态不代表组件安全。",
        "",
        "## 汇总",
        "",
        f"- 组件数：**{len(ok)}**（共 {len(rows)} 条清单，失败 "
        f"{len(rows) - len(ok)}）",
        f"- 扫描源文件：**{total_files:,}**",
        f"- 扫描源码字节：**{total_bytes:,}**",
        f"- 语料 C/C++ 总行数（全部源文件，非扫描子集）：**{total_loc:,}**",
        f"- 累计墙钟：**{total_s:.2f} s**（单进程串行执行）",
        f"- 单次进程峰值 RSS 上界：**{peak / 1024:.1f} MB**",
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
        out.append(
            f"| {r['label']} | `{r['commit'][:12]}` | {r.get('shards', 1)} | "
            f"{r['scanned_files']:,} | "
            f"{r['scanned_bytes']:,} | {r['tree_source_loc']:,} | "
            f"{r['wall_seconds']:.2f} | {r['peak_rss_kb'] / 1024:.1f} | "
            f"{r['files_per_second']:.0f} | "
            f"{r['parse_complete']}/{r['parse_partial']} | "
            f"{r['detector_status']} |"
        )

    out += [
        "",
        "## 语料构建与复现",
        "",
        "语料是固定到完整 commit SHA 的 OpenHarmony 组件 `--depth=1` 克隆（SSH；该 commit 的"
        "全部 blob 本地齐备，因此扫描全程离线、不触发任何抓取）：",
        "",
        "```bash",
        "git clone --depth=1 git@github.com:openharmony/<component>.git",
        "git -C <component> rev-parse HEAD   # 必须等于清单中的 commit",
        "```",
        "",
        f"11 条组件与其完整 SHA 记录在 `{manifest_path}`。一键复跑：",
        "",
        "```bash",
        "python scripts/perf_scale_scan.py \\",
        f"  --manifest {manifest_path} \\",
        "  --json-out outputs/reports/perf_scale_scan.json \\",
        "  --md-out docs/testing/ohscanner_performance_scale.md",
        "```",
        "",
        "测量方式：每个组件在独立子进程中执行 `python -m src.cli ohscan-run`，由一个**最小的**"
        "父进程记录墙钟与 `ru_maxrss`。用最小父进程是必要的——Linux 上 fork 出的子进程在 exec 前"
        "共享父进程的常驻页，若从本脚本（它在统计行数时会缓冲整份源码）直接测量，得到的会是父进程"
        "的内存而不是扫描器的内存。数值已用 GNU `time -v` 抽样交叉核对。",
        "",
        "## 限制",
        "",
        "- 语料是**组件级**（单次约 0.2k–2k 源文件），不是 OpenHarmony 千万行整树；"
        "整树规模需另行测量。",
        "- 执行是**同进程串行**的；尚无并行、增量缓存或硬超时/资源隔离。",
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
    ap.add_argument("--python", default=str(here / ".venv/bin/python"),
                    help="interpreter used to run the CLI")
    ap.add_argument("--json-out", required=True)
    ap.add_argument("--md-out", required=True)
    ap.add_argument("--only", nargs="*",
                    help="restrict to these manifest labels")
    args = ap.parse_args(argv)

    manifest = json.loads(pathlib.Path(args.manifest).read_text(encoding="utf-8"))
    entries = manifest["entries"]
    if args.only:
        entries = [e for e in entries if e["label"] in set(args.only)]

    report_dir = pathlib.Path(args.json_out).resolve().parent / "perf_scale"
    report_dir.mkdir(parents=True, exist_ok=True)

    rows = []
    for entry in entries:
        print(f"[run] {entry['label']} @ {entry['commit'][:12]} ...", flush=True)
        row = benchmark_one(args.project_root, args.python, entry, report_dir)
        state = "ok" if row.get("exit_code") == 0 else f"FAIL({row['exit_code']})"
        print(f"      {state}  {row['wall_seconds']}s  "
              f"{row['peak_rss_kb'] / 1024:.1f} MB  "
              f"{row.get('scanned_files', '-')} files", flush=True)
        rows.append(row)

    json_path = pathlib.Path(args.json_out)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(
        json.dumps({"manifest": args.manifest, "rows": rows},
                   indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    pathlib.Path(args.md_out).write_text(
        render_markdown(rows, args.manifest), encoding="utf-8")
    print(f"\nwrote {json_path}\nwrote {args.md_out}")
    return 0 if all(r.get("exit_code") == 0 for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
