#!/usr/bin/env python3
"""C11 performance and bounded-scope admission experiment.

This file is an independent research harness. It uses the production source
loader, syntax frontend and detector runner read-only. It does not modify the
scanner implementation and never performs Git writes.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import pathlib
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict
from typing import Any, Iterable

ROOT = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
OUT = pathlib.Path(__file__).resolve().parent / "out"
CACHE_ROOT = pathlib.Path(__file__).resolve().parent / "cache"
GIT_ENV = {
    **os.environ,
    "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_NO_LAZY_FETCH": "1",
    "GIT_ALLOW_PROTOCOL": "",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_OPTIONAL_LOCKS": "0",
}
BASE_COMMIT = "ab30df6a01797af455d2abbbc9533ab15964ee68"


def _json_default(value: Any):
    if hasattr(value, "__dict__"):
        return {k: v for k, v in vars(value).items() if not k.startswith("_")}
    raise TypeError(type(value).__name__)


def write_json(path: pathlib.Path, payload: Any):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=_json_default) + "\n", encoding="utf-8")


def _windows_peak_rss(pid: int) -> int:
    from ctypes import wintypes
    class PMC(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(PMC), wintypes.DWORD]
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
    handle = kernel32.OpenProcess(0x0410, False, pid)
    if not handle:
        return 0
    try:
        counters = PMC()
        counters.cb = ctypes.sizeof(counters)
        if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
            return 0
        return int(counters.PeakWorkingSetSize)
    finally:
        kernel32.CloseHandle(handle)


def peak_rss_bytes_for_process(proc) -> int:
    return _windows_peak_rss(proc.pid) if os.name == "nt" else 0


def peak_rss_bytes() -> int:
    if os.name == "nt":
        return _windows_peak_rss(os.getpid())
    import resource
    return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) * 1024


def measured(fn):
    before = peak_rss_bytes()
    start = time.perf_counter()
    result = fn()
    wall = time.perf_counter() - start
    after = peak_rss_bytes()
    return result, {"wall_seconds": wall, "peak_rss_bytes": max(before, after)}


def fake_blob_oid(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def synthetic_sources(count: int, total_bytes: int | None = None, *, prefix="src"):
    """Deterministic in-memory GitSource-like inputs for limit and cache tests."""
    from src.ohscanner.git_source import GitSource
    base = b"void f_%d(char *d, const char *s) { strcpy(d, s); }\n"
    items = []
    sizes = [None] * count
    if total_bytes is not None:
        per = total_bytes // count
        remainder = total_bytes % count
        sizes = [per + (1 if i < remainder else 0) for i in range(count)]
    for i in range(count):
        body = base % i
        if sizes[i] is not None:
            if sizes[i] < len(body):
                raise ValueError("synthetic size is smaller than source body")
            body += b"//" + b"x" * (sizes[i] - len(body) - 2) + b"\n"
            body = body[:sizes[i]]
        else:
            body += b"// filler " + str(i).encode("ascii") + b"\n"
        path = f"{prefix}/shard-{i % 8:02d}/file-{i:04d}.cpp"
        items.append(GitSource(path, "cpp", fake_blob_oid(body), body))
    return tuple(sorted(items, key=lambda item: item.path))


def identity_signature_rows(rows):
    rows = sorted(rows)
    return hashlib.sha256(json.dumps(rows, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest(), rows


def identity_signature(sources):
    import hashlib as _hashlib
    rows = []
    for s in sorted(sources, key=lambda x: x.path):
        rows.append([s.path, s.language, s.oid, _hashlib.sha256(s.data).hexdigest()])
    return _hashlib.sha256(json.dumps(rows, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest(), rows


def parse_signature(units, coverage):
    import hashlib as _hashlib
    rows = [[u.path, u.language, u.sha256, u.parse_status, list(u.parse_issues)] for u in units]
    payload = {"units": rows, "coverage": coverage}
    return _hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def diagnostic_signature(reports):
    import hashlib as _hashlib
    rows = []
    for report in reports:
        for d in report.diagnostics:
            rows.append([report.tool, d.diagnostic_id, d.file, d.line, d.rule_id, d.candidate_cwe, d.source_sha256])
    rows.sort()
    return _hashlib.sha256(json.dumps(rows, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest(), rows


def parser_fingerprint():
    from src.ohscanner.indexing import environment_fingerprint
    env = environment_fingerprint()
    return {
        "python": env["python"],
        "git": env["git"],
        "parsers": env["parsers"],
        "parse_profile": env["parse_profile"],
        "macro_expansion": env["macro_expansion"],
    }


def build_context(sources, *, cache_dir: pathlib.Path | None = None):
    sources = tuple(sorted(sources, key=lambda item: item.path))
    """Build the same context shape as prepare_git_context, optionally using a file cache."""
    from src.ohscanner.contracts import ScanContext, ScanRequest
    from src.ohscanner.facts import build_syntax_facts
    from src.ohscanner.fixture import snapshot_digest
    from src.ohscanner.frontend import index_sources

    if cache_dir is None:
        units, ast, coverage = index_sources(sources)
    else:
        cache_dir.mkdir(parents=True, exist_ok=True)
        fingerprint = parser_fingerprint()
        units, ast = [], {}
        for source in sources:
            key = hashlib.sha256(json.dumps({
                "oid": source.oid, "language": source.language,
                "profile": fingerprint,
                "source_sha256": hashlib.sha256(source.data).hexdigest(),
            }, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
            path = cache_dir / (key + ".json")
            if path.exists():
                item = json.loads(path.read_text(encoding="utf-8"))
            else:
                one_units, one_ast, _ = index_sources((source,))
                item = {"unit": asdict(one_units[0]), "ast": one_ast[source.path]}
                write_json(path, item)
            unit_data = item["unit"]
            unit_data["parse_issues"] = tuple(unit_data["parse_issues"])
            from src.ohscanner.contracts import SourceUnit
            units.append(SourceUnit(**unit_data))
            ast[source.path] = item["ast"]
        from collections import Counter
        coverage = {
            "parsing_status": dict(sorted(Counter(u.parse_status for u in units).items())),
            "languages": dict(sorted(Counter(u.language for u in units).items())),
        }
    units = tuple(units)
    digest = snapshot_digest(units)
    context = ScanContext(
        request=ScanRequest(
            request_id="c11-perf:" + digest[:16],
            repository="c11/in-memory-fixed-source",
            commit=BASE_COMMIT,
            snapshot_sha256=digest,
            target_id="current-component:c11/in-memory-fixed-source",
            profile_id="light-ast",
            provenance="fixture",
        ),
        units=units,
        shared_facts={
            "ast": ast,
            "source_blob_oid": {s.path: s.oid for s in sources if s.archive_binding is None},
            "source_archive_binding": {s.path: s.archive_binding for s in sources if s.archive_binding is not None},
            "facts_v1": build_syntax_facts(ast),
            "coverage": coverage,
        },
    )
    return context, coverage


def compact_result(value):
    if isinstance(value, dict):
        skip = {"diagnostic_rows", "parse_rows", "detector_sidecar", "source_rows"}
        out = {k: compact_result(v) for k, v in value.items() if k not in skip}
        if "shards" in value and isinstance(value["shards"], list):
            out["shards"] = [{
                "source_identity_sha256": x.get("source_identity_sha256"),
                "parse_signature_sha256": x.get("parse_signature_sha256"),
                "diagnostic_signature_sha256": x.get("diagnostic_signature_sha256"),
                "diagnostic_count": x.get("diagnostic_count"),
            } for x in value["shards"]]
        return out
    if isinstance(value, list):
        return [compact_result(x) for x in value]
    return value


def diagnostic_signature_rows(rows):
    rows = sorted(rows)
    return hashlib.sha256(json.dumps(rows, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest(), rows


def run_detector(sources, *, cache_dir=None):
    from src.ohscanner.detectors.catalog import build_registry
    from src.ohscanner.runner import run_all_with_coverage
    context, coverage = build_context(sources, cache_dir=cache_dir)
    registry = build_registry(("ohscanner.example.cpp.copy-calls",), allow_examples=True)
    reports, sidecar = run_all_with_coverage(context, registry)
    return {
        "source_identity_sha256": identity_signature(sources)[0],
        "parse_signature_sha256": parse_signature(context.units, coverage),
        "diagnostic_signature_sha256": diagnostic_signature(reports)[0],
        "diagnostic_rows": diagnostic_signature(reports)[1],
        "parse_rows": [[u.path, u.language, u.sha256, u.parse_status, list(u.parse_issues)] for u in context.units],
        "diagnostic_count": sum(r.diagnostic_count for r in reports),
        "coverage": coverage,
        "detector_sidecar": sidecar,
    }


def _tree_bytes(sources):
    return b"".join(f"100644 blob {s.oid} {len(s.data)}\t{s.path}\0".encode("utf-8") for s in sources)


def _fake_load(sources, *, unbatched=False):
    """Exercise production load_git_sources with an in-memory read-only Git view."""
    import src.ohscanner.git_source as gs
    old_resolve, old_git, old_batch = gs.resolve_commit, gs._git, gs._git_batch_blobs
    by_oid = {s.oid: s for s in sources}
    calls = []
    def resolve(_repo, commit):
        return commit, "b" * 40
    def fake_git(_repo, *args):
        if args[:2] == ("ls-tree", "-r"):
            return _tree_bytes(sources)
        raise RuntimeError(args)
    def fake_batch(_repo, requests, timeout=30):
        calls.append(len(requests))
        if unbatched and len(requests) != 1:
            raise AssertionError("reference mode must request one blob at a time")
        return tuple(by_oid[oid].data for _, oid, _ in requests)
    try:
        gs.resolve_commit, gs._git, gs._git_batch_blobs = resolve, fake_git, fake_batch
        result = gs.load_git_sources(pathlib.Path("in-memory"), BASE_COMMIT, (".",))
        return result, calls
    finally:
        gs.resolve_commit, gs._git, gs._git_batch_blobs = old_resolve, old_git, old_batch


def limit_case(sizes: list[int]):
    import src.ohscanner.git_source as gs
    sources = []
    for i, size in enumerate(sizes):
        body = b"void f(void) {}\n" + b"//" + b"x" * (size - 15 - 2) + b"\n"
        body = body[:size]
        sources.append(gs.GitSource(f"f{i:04d}.cpp", "cpp", fake_blob_oid(body), body))
    try:
        (commit, tree, loaded, inventory), calls = _fake_load(tuple(sources))
        return {
            "status": "accepted", "selected_source_files": len(loaded),
            "selected_source_bytes": sum(len(s.data) for s in loaded),
            "inventory": inventory, "batch_calls": calls,
        }
    except ValueError as error:
        return {"status": "rejected", "error": str(error), "limit": "M1 bounded scope"}


def run_worker(case: str, output: pathlib.Path, repeat: int):
    OUT.mkdir(parents=True, exist_ok=True)
    CACHE_ROOT.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {"case": case, "repeat": repeat, "environment": parser_fingerprint()}
    if case in {"full_no_cache", "shard_no_cache", "cache_cold", "cache_warm", "limit_1999", "limit_2000", "limit_2001", "limit_total_32mib", "limit_total_32mib_plus_1", "limit_blob_exact", "limit_blob_plus_1"}:
        sources = synthetic_sources(2000)
        if case == "shard_no_cache":
            groups = [tuple(s for s in sources if f"shard-{i:02d}" in s.path) for i in range(8)]
            def fn():
                result = run_detector(sources)
                shard_results = [run_detector(g) for g in groups]
                merged = []
                for r in shard_results:
                    merged.append(r)
                return {"full": result, "shards": merged,
                        "invariant": (
                            result["source_identity_sha256"] == identity_signature(sum(groups, ()))[0]
                            and result["diagnostic_signature_sha256"] == diagnostic_signature_rows(
                                sum((r["diagnostic_rows"] for r in shard_results), []))[0]
                            and sorted(result["parse_rows"]) == sorted(sum((r["parse_rows"] for r in shard_results), []))
                        )}
        elif case == "cache_cold":
            cache = pathlib.Path(tempfile.mkdtemp(prefix="c11-cold-", dir=str(CACHE_ROOT)))
            def fn():
                return run_detector(sources, cache_dir=cache)
        elif case == "cache_warm":
            cache = pathlib.Path(tempfile.mkdtemp(prefix="c11-warm-", dir=str(CACHE_ROOT)))
            run_detector(sources, cache_dir=cache)
            def fn():
                return run_detector(sources, cache_dir=cache)
        elif case == "limit_1999":
            def fn():
                return limit_case([1024] * 1999)
        elif case == "limit_2000":
            def fn():
                return limit_case([1024] * 2000)
        elif case == "limit_2001":
            def fn():
                return limit_case([1024] * 2001)
        elif case == "limit_total_32mib":
            def fn():
                return limit_case([1024 * 1024] * 32)
        elif case == "limit_total_32mib_plus_1":
            def fn():
                return limit_case([1024 * 1024] * 32 + [1])
        elif case == "limit_blob_exact":
            def fn():
                return limit_case([1024 * 1024, 1024])
        elif case == "limit_blob_plus_1":
            def fn():
                return limit_case([1024 * 1024 + 1, 1024])
        else:
            def fn():
                return run_detector(sources)
    elif case in {"batch_real", "unbatch_real"}:
        from src.ohscanner.git_source import _git_batch_blobs, load_git_sources
        _, _, sources, _ = load_git_sources(ROOT, BASE_COMMIT, ("src",))
        requests = tuple((s.path, s.oid, len(s.data)) for s in sources)
        if case == "batch_real":
            def fn():
                data = _git_batch_blobs(ROOT, requests)
                return {"source_identity_sha256": identity_signature(tuple(type(s)(s.path, s.language, s.oid, d) for s, d in zip(sources, data)))[0], "count": len(data)}
        else:
            def fn():
                data = tuple(_git_batch_blobs(ROOT, (req,))[0] for req in requests)
                return {"source_identity_sha256": identity_signature(tuple(type(s)(s.path, s.language, s.oid, d) for s, d in zip(sources, data)))[0], "count": len(data)}
    elif case in {"cli_index_full", "cli_index_shards", "cli_detector_full"}:
        repo = str(ROOT)
        python = sys.executable
        def run_cli(includes):
            label = "full" if includes == (".",) else "shard-" + hashlib.sha256("|".join(includes).encode()).hexdigest()[:8]
            json_out = OUT / f"cli-{case}-{repeat}-{label}.json"
            md_out = OUT / f"cli-{case}-{repeat}-{label}.md"
            cmd = [python, "-m", "src.cli.main", "ohscan-index", "--repo-dir", repo,
                   "--repository", "c11/perf-read-only", "--commit", BASE_COMMIT,
                   "--json-out", str(json_out), "--md-out", str(md_out)]
            for x in includes:
                cmd.extend(["--include", x])
            start = time.perf_counter()
            proc = subprocess.Popen(cmd, cwd=repo, env=GIT_ENV, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True)
            peak = 0
            while proc.poll() is None:
                peak = max(peak, peak_rss_bytes_for_process(proc))
                time.sleep(0.005)
            stdout, stderr = proc.communicate()
            wall = time.perf_counter() - start
            if proc.returncode != 0:
                raise RuntimeError(stderr[-1000:])
            data = json.loads(json_out.read_text(encoding="utf-8"))
            source_rows = [[u["file"], u["language"], u["sha256"], u.get("blob_oid"), json.dumps(u.get("archive_binding"), sort_keys=True)]
                           for u in data["source_units"]]
            parse_rows = [[u["file"], u["language"], u["sha256"], u["parse_status"], u.get("parse_issues", [])]
                          for u in data["source_units"]]
            return {"wall_seconds": wall, "peak_rss_bytes": peak,
                    "source_count": data["scope"]["selected_source_files"],
                    "source_bytes": data["scope"]["selected_source_bytes"],
                    "parse": data["coverage"],
                    "source_identity_sha256": identity_signature_rows(source_rows)[0],
                    "coverage_signature_sha256": identity_signature_rows(parse_rows)[0],
                    "source_rows": source_rows, "parse_rows": parse_rows}
        if case == "cli_index_full":
            fn = lambda: run_cli(("src",))
        elif case == "cli_index_shards":
            def fn():
                full = run_cli(("src",))
                tree_paths = subprocess.check_output(
                    ["git", "-C", str(ROOT), "ls-tree", "-r", "--name-only", BASE_COMMIT, "src"],
                    env=GIT_ENV, text=True).splitlines()
                top_names = sorted({path.split("/", 2)[1] for path in tree_paths if "/" in path})
                top_paths = []
                for name in top_names:
                    candidate = "src/" + name
                    try:
                        __import__("src.ohscanner.git_source", fromlist=["load_git_sources"]).load_git_sources(ROOT, BASE_COMMIT, (candidate,))
                    except ValueError:
                        continue
                    top_paths.append(candidate)
                shards = [run_cli((x,)) for x in top_paths]
                merged_source_rows = sum((r["source_rows"] for r in shards), [])
                merged_parse_rows = sum((r["parse_rows"] for r in shards), [])
                return {
                    "full": full, "shards": shards,
                    "invariant": (
                        full["source_identity_sha256"] == identity_signature_rows(merged_source_rows)[0]
                        and full["coverage_signature_sha256"] == identity_signature_rows(merged_parse_rows)[0]
                    ),
                }
        else:
            def fn():
                json_out = OUT / f"cli-detector-{repeat}.json"
                md_out = OUT / f"cli-detector-{repeat}.md"
                cmd = [python, "-m", "src.cli.main", "ohscan-run", "--repo-dir", repo,
                       "--repository", "c11/perf-read-only", "--commit", BASE_COMMIT,
                       "--include", "src", "--detector", "ohscanner.example.cpp.copy-calls",
                       "--allow-example-detectors", "--json-out", str(json_out), "--md-out", str(md_out)]
                start = time.perf_counter()
                proc = subprocess.run(cmd, cwd=repo, env=GIT_ENV, capture_output=True, text=True)
                wall = time.perf_counter() - start
                if proc.returncode != 0:
                    raise RuntimeError(proc.stderr[-1000:])
                data = json.loads(json_out.read_text(encoding="utf-8"))
                return {"wall_seconds": wall, "diagnostic_count": data["diagnostic_count"], "scope": data["scope"]}
    else:
        raise ValueError("unknown case: " + case)
    result, metrics = measured(fn)
    payload.update(metrics)
    payload["result"] = compact_result(result)
    write_json(output, payload)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--worker")
    ap.add_argument("--output", type=pathlib.Path)
    ap.add_argument("--repeat", type=int, default=0)
    ap.add_argument("--out-dir", type=pathlib.Path, default=OUT)
    args = ap.parse_args(argv)
    if args.worker:
        run_worker(args.worker, args.output, args.repeat)
        return 0
    cases = [
        ("batch_real", 5), ("unbatch_real", 5),
        ("full_no_cache", 5), ("shard_no_cache", 5),
        ("cache_cold", 5), ("cache_warm", 5),
        ("cli_index_full", 3), ("cli_index_shards", 3), ("cli_detector_full", 3),
        ("limit_1999", 3), ("limit_2000", 3), ("limit_2001", 3),
        ("limit_total_32mib", 3), ("limit_total_32mib_plus_1", 3),
        ("limit_blob_exact", 3), ("limit_blob_plus_1", 3),
    ]
    rows = []
    for case, reps in cases:
        for repeat in range(reps):
            path = args.out_dir / "raw" / f"{case}-{repeat:02d}.json"
            cmd = [sys.executable, str(pathlib.Path(__file__).resolve()), "--worker", case,
                   "--output", str(path), "--repeat", str(repeat)]
            proc = subprocess.run(cmd, cwd=str(ROOT), env=GIT_ENV, capture_output=True, text=True)
            row = {"case": case, "repeat": repeat, "returncode": proc.returncode,
                   "stdout": proc.stdout[-1000:], "stderr": proc.stderr[-1000:]}
            if path.exists():
                row["measurement"] = json.loads(path.read_text(encoding="utf-8"))
            rows.append(row)
    write_json(args.out_dir / "raw-index.json", rows)
    summary = {"rows": []}
    for case, reps in cases:
        values = [r["measurement"] for r in rows if r["case"] == case and "measurement" in r and r["returncode"] == 0]
        walls = [v["wall_seconds"] for v in values]
        rss = [v["peak_rss_bytes"] for v in values]
        if walls:
            summary["rows"].append({"case": case, "runs": len(values),
                "wall_median_seconds": statistics.median(walls),
                "wall_p95_seconds": max(walls),
                "rss_median_bytes": statistics.median(rss),
                "rss_tail_bytes": max(rss),
                "first_result": values[0].get("result")})
    write_json(args.out_dir / "summary.json", summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())






