"""Shared C/C++ and JS/TS syntax coverage; unsupported ArkTS stays partial.

Syntax eligibility is not a type, manifest, permission or security proof.
"""

from collections import Counter
from hashlib import sha256
import json
from time import perf_counter, process_time

from src.parser.ast import parse_source
from .contracts import SourceUnit
from .git_source import GitSource
from .detectors.interface.arkts_js import frontend as script_frontend


def index_sources(sources: tuple[GitSource, ...], ast_cache=None, metrics=None):
    parse_started = perf_counter()
    frontend_cpu_started = process_time()
    units = []
    ast_summary = {}
    parse_files = 0
    parse_seconds = 0.0
    parse_cpu_seconds = 0.0
    for source in sources:
        text = source.data.decode("utf-8")
        status = "not_run"
        issues = []
        if source.language in ("c", "cpp"):
            try:
                if ast_cache is not None and source.archive_binding is None:
                    index = ast_cache.load(source.oid, source.language, source.data)
                else:
                    if ast_cache is not None:
                        ast_cache.bypass()
                    index = None
                if index is None:
                    started = perf_counter()
                    cpu_started = process_time()
                    parse_files += 1
                    index = parse_source(text, language=source.language)
                    parse_seconds += perf_counter() - started
                    parse_cpu_seconds += process_time() - cpu_started
                    if ast_cache is not None and source.archive_binding is None:
                        ast_cache.store(source.oid, source.language, source.data, index)
                status = index.parse_status
                issues = [json.dumps(item, sort_keys=True) for item in index.parse_issues]
                ast_summary[source.path] = {
                    "parse_status": status,
                    "functions": [item.__dict__ for item in index.functions],
                    "calls": [item.__dict__ for item in index.calls],
                    "variables": [item.__dict__ for item in index.variables],
                }
            except (RuntimeError, ValueError) as error:
                status = "failed"
                issues = [type(error).__name__ + ": " + str(error)[:300]]
                ast_summary[source.path] = {"parse_status": "failed",
                                            "functions": [], "calls": [], "variables": []}
        elif source.language in ("js", "ts", "arkts"):
            started = perf_counter()
            cpu_started = process_time()
            parsed = script_frontend(SourceUnit(
                path=source.path, language=source.language, text=text,
                sha256=sha256(source.data).hexdigest(), parse_status="not_run"))
            parse_seconds += perf_counter() - started
            parse_cpu_seconds += process_time() - cpu_started
            parse_files += 1
            status = parsed.status if parsed.status in ("complete", "partial") else "not_run"
            if parsed.status == "unsupported":
                issues = ["Required grammar unavailable; source indexed as text only"]
            elif parsed.error_nodes:
                issues = [f"Tree-sitter recovered {parsed.error_nodes} error/missing node(s)"]
        else:
            issues = ["No language frontend configured; source indexed as text only"]
        units.append(SourceUnit(
            path=source.path, language=source.language, text=text,
            sha256=sha256(source.data).hexdigest(),
            parse_status=status, parse_issues=tuple(issues),
        ))
    counts = dict(sorted(Counter(unit.parse_status for unit in units).items()))
    languages = dict(sorted(Counter(unit.language for unit in units).items()))
    if metrics is not None:
        metrics["parse_seconds"] = parse_seconds
        metrics["frontend_seconds"] = perf_counter() - parse_started
        metrics["parse_cpu_seconds"] = parse_cpu_seconds
        metrics["frontend_cpu_seconds"] = process_time() - frontend_cpu_started
        metrics["parse_files"] = parse_files
        metrics["indexed_files"] = len(units)
        metrics["cache"] = (ast_cache.report_stats() if ast_cache is not None else
                             {"hits": 0, "misses": 0, "bypassed": 0,
                              "invalid": 0, "writes": 0, "evictions": 0,
                              "oversize_not_stored": 0, "cleared_entries": 0,
                              "cleared_bytes": 0, "cleanup_errors": 0,
                              "cache_bytes": 0, "max_bytes": None,
                              "hit_rate": None})
    return tuple(units), ast_summary, {"parsing_status": counts, "languages": languages}
