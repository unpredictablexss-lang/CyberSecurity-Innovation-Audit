"""Conservative fixed-commit change planning.

This module deliberately never reuses detector output. The current detector
contracts do not declare a sound dependency model, so a diff plan is diagnostic
and the execution mode falls back to a complete scan until such proof exists.
"""
from __future__ import annotations

import subprocess
import re
import posixpath
from collections import defaultdict, deque
from pathlib import Path
from time import perf_counter, process_time

_INCLUDE = re.compile(rb"^\s*#\s*include\s*([<\"])([^>\"]+)[>\"]", re.MULTILINE)
_CALL_TAIL = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^;{}()]*>)?\s*$")


def _git(repo, *args):
    from .git_source import _git_environment
    result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True,
                            timeout=30, stdin=subprocess.DEVNULL, env=_git_environment())
    if result.returncode:
        raise ValueError(result.stderr.decode("utf-8", "replace")[:1000])
    return result.stdout


def _include_index(sources):
    paths = {source.path for source in sources}
    reverse = defaultdict(set)
    unresolved = []
    external = []
    for source in sources:
        for match in _INCLUDE.finditer(source.data):
            delimiter, raw_name = match.groups()
            name = raw_name.decode("utf-8", "replace").replace("\\", "/")
            if delimiter == b"<":
                external.append({"including_file": source.path, "include": name})
                continue
            candidates = {
                posixpath.normpath(posixpath.join(posixpath.dirname(source.path), name)),
                posixpath.normpath(name),
            }
            found = sorted(path for path in candidates if path in paths)
            if len(found) == 1:
                reverse[found[0]].add(source.path)
            elif len(found) > 1:
                unresolved.append({"including_file": source.path, "include": name,
                                   "reason": "ambiguous_project_header"})
            else:
                unresolved.append({"including_file": source.path, "include": name,
                                   "reason": "unresolved_project_header"})
    return reverse, unresolved, external


def _dependent_closure(changed_paths, *reverse_indexes):
    seen = set(changed_paths)
    queue = deque(seen)
    while queue:
        dependency = queue.popleft()
        for reverse in reverse_indexes:
            for includer in reverse.get(dependency, ()):
                if includer not in seen:
                    seen.add(includer)
                    queue.append(includer)
    return seen


def _call_symbol_index(ast_by_path):
    """Build a conservative file-level index over syntax-only names.

    Qualified/member call expressions are reduced to their terminal identifier
    so they over-approximate candidates. This index never resolves overloads,
    namespaces, macros, function pointers or virtual dispatch.
    """
    definitions = defaultdict(set)
    callers = defaultdict(set)
    unresolved = []
    for path, ast in sorted(ast_by_path.items()):
        if ast.get("parse_status") != "complete":
            unresolved.append({"file": path, "reason": "incomplete_ast"})
        for function in ast.get("functions", ()):
            name = function.get("name", "")
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                definitions[name].add(path)
            else:
                unresolved.append({"file": path, "reason": "unresolved_function_name"})
        for call in ast.get("calls", ()):
            expression = call.get("name", "")
            match = _CALL_TAIL.search(expression)
            if match is None:
                unresolved.append({"file": path, "reason": "unresolved_call_expression"})
                continue
            callers[match.group(1)].add(path)
    ambiguous = sorted(name for name, paths in definitions.items() if len(paths) > 1)
    return definitions, callers, unresolved, ambiguous


def _call_dependency_closure(seed_paths, base_ast, head_ast, max_files=2000, max_edges=50000):
    """Expand changed files through syntax-call candidates on both endpoints."""
    base_defs, base_callers, base_unknown, base_ambiguous = _call_symbol_index(base_ast)
    head_defs, head_callers, head_unknown, head_ambiguous = _call_symbol_index(head_ast)
    definitions = defaultdict(set)
    callers = defaultdict(set)
    for source in (base_defs, head_defs):
        for name, paths in source.items():
            definitions[name].update(paths)
    for source in (base_callers, head_callers):
        for name, paths in source.items():
            callers[name].update(paths)
    symbols_by_file = defaultdict(set)
    for name, paths in definitions.items():
        for path in paths:
            symbols_by_file[path].add(name)
    impacted = set(seed_paths)
    if len(impacted) > max_files:
        return impacted, set(), base_unknown + head_unknown, sorted(set(base_ambiguous + head_ambiguous)), True
    queue = deque(sorted(impacted))
    edges = set()
    while queue:
        path = queue.popleft()
        for name in symbols_by_file.get(path, ()):
            for caller in callers.get(name, ()):
                edges.add((path, caller, name))
                if len(edges) > max_edges:
                    return impacted, edges, base_unknown + head_unknown, sorted(set(base_ambiguous + head_ambiguous)), True
                if caller not in impacted:
                    impacted.add(caller)
                    if len(impacted) > max_files:
                        return impacted, edges, base_unknown + head_unknown, sorted(set(base_ambiguous + head_ambiguous)), True
                    queue.append(caller)
    unknown = base_unknown + head_unknown
    ambiguous = sorted(set(base_ambiguous + head_ambiguous))
    return impacted, edges, unknown, ambiguous, False


def _cache_counter_delta(before, after):
    if before is None or after is None:
        return None
    return {key: int(after.get(key, 0)) - int(before.get(key, 0))
            for key in sorted(set(before) | set(after))
            if isinstance(before.get(key, 0), (int, float))
            and isinstance(after.get(key, 0), (int, float))}


def plan_fixed_commit_diff(repo, base_commit, head_commit, includes=(".",), *,
                           head_sources=None, head_inventory=None, head_ast=None,
                           ast_cache=None):
    """Return a bounded diff plan and why it cannot yet reduce scan coverage."""
    if (not isinstance(base_commit, str) or not isinstance(head_commit, str)
            or not re.fullmatch(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", base_commit)
            or not re.fullmatch(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", head_commit)):
        raise ValueError("incremental endpoints must be complete immutable Git object IDs")
    base = _git(repo, "rev-parse", "--verify", base_commit + "^{commit}").decode().strip()
    head = _git(repo, "rev-parse", "--verify", head_commit + "^{commit}").decode().strip()
    if len(base) not in {40, 64} or len(head) not in {40, 64}:
        raise ValueError("incremental endpoints must resolve to full commit IDs")
    from .git_source import _git_environment
    ancestor = subprocess.run(["git", "-C", str(repo), "merge-base", "--is-ancestor", base, head],
                              capture_output=True, timeout=30, stdin=subprocess.DEVNULL,
                              env=_git_environment())
    if ancestor.returncode:
        raise ValueError("incremental base must be an ancestor of head")
    diff_error = None
    try:
        raw = _git(repo, "diff", "--name-status", "-M", "-z", base, head, "--")
        tokens = raw.decode("utf-8", "strict").split("\0")
    except (ValueError, UnicodeError, OSError, subprocess.TimeoutExpired) as error:
        raw = b""
        tokens = [""]
        diff_error = type(error).__name__ + ": " + str(error)[:300]
    changes, i = [], 0
    while i < len(tokens) and tokens[i]:
        status = tokens[i]
        count = 2 if status.startswith(("R", "C")) else 1
        paths = tokens[i + 1:i + 1 + count]
        if len(paths) != count:
            raise ValueError("malformed Git diff name-status record")
        changes.append({"status": status, "old_path": paths[0], "new_path": paths[-1]})
        i += count + 1
        if len(changes) > 20000:
            raise ValueError("incremental diff exceeds 20000 path changes")

    included = lambda path: any(prefix == "." or path == prefix or path.startswith(prefix.rstrip("/") + "/")
                                 for prefix in includes)
    scoped = [row for row in changes if included(row["new_path"]) or included(row["old_path"])]
    config_suffixes = ("CMakeLists.txt", "BUILD.gn", "BUILD.gni", "Makefile", ".cmake", ".gn", ".gni")
    config_paths = sorted({path for row in scoped for path in (row["old_path"], row["new_path"])
                           if path and (path.endswith(config_suffixes) or path.endswith((".json", ".yaml", ".yml"))
                                        and any(word in path.lower() for word in ("build", "compile", "config")))})
    # Resolve tracked quoted includes on both endpoints. The union is needed for
    # removed/renamed headers whose dependents only appear in the base graph.
    from .git_source import load_git_sources
    base_load_error = None
    try:
        _, _, base_sources, base_inventory = load_git_sources(Path(repo), base, tuple(includes))
    except (ValueError, OSError, UnicodeError, subprocess.TimeoutExpired) as error:
        # A verified head scan remains useful even if baseline dependencies
        # cannot be indexed. Record the reason and force the safe full-scan path.
        base_sources = ()
        base_inventory = {"skipped": [{"reason": "base_dependency_inventory_unavailable"}],
                          "source_archives": []}
        base_load_error = type(error).__name__ + ": " + str(error)[:300]
    if head_sources is None or head_inventory is None:
        _, _, loaded_head_sources, loaded_head_inventory = load_git_sources(Path(repo), head, tuple(includes))
        head_sources = loaded_head_sources if head_sources is None else head_sources
        head_inventory = loaded_head_inventory if head_inventory is None else head_inventory
    base_reverse, base_unresolved, base_external = _include_index(base_sources)
    head_reverse, head_unresolved, head_external = _include_index(head_sources)
    changed = {path for row in scoped for path in (row["old_path"], row["new_path"]) if path}
    include_impact = _dependent_closure(changed, base_reverse, head_reverse)
    # Reuse head syntax facts already built by the normal scan. Parse the fixed
    # base endpoint only for C/C++ so candidate callers can be conservatively
    # expanded without treating lexical matches as a complete dependency proof.
    from .frontend import index_sources
    base_cpp = tuple(source for source in base_sources if source.language in ("c", "cpp"))
    base_index_metrics = {}
    base_index_wall_started, base_index_cpu_started = perf_counter(), process_time()
    base_cache_before = dict(ast_cache.stats) if ast_cache is not None else None
    _, base_ast, _ = index_sources(base_cpp, ast_cache=ast_cache, metrics=base_index_metrics)
    base_cache_after = dict(ast_cache.stats) if ast_cache is not None else None
    base_index_metrics["cache_counter_delta"] = _cache_counter_delta(base_cache_before, base_cache_after)
    base_index_metrics["total_wall_seconds"] = perf_counter() - base_index_wall_started
    base_index_metrics["total_cpu_seconds"] = process_time() - base_index_cpu_started
    if head_ast is None:
        head_cpp = tuple(source for source in head_sources if source.language in ("c", "cpp"))
        head_index_metrics = {}
        head_cache_before = dict(ast_cache.stats) if ast_cache is not None else None
        _, head_ast, _ = index_sources(head_cpp, ast_cache=ast_cache, metrics=head_index_metrics)
        head_cache_after = dict(ast_cache.stats) if ast_cache is not None else None
        head_index_metrics["cache_counter_delta"] = _cache_counter_delta(head_cache_before, head_cache_after)
    else:
        head_index_metrics = {"indexed_from_scan_facts": True}
        head_ast = {path: value for path, value in head_ast.items()
                    if value.get("language", "cpp") in ("c", "cpp")}
    call_impact, call_edges, call_unknown, ambiguous_symbols, truncated_calls = _call_dependency_closure(
        changed, base_ast, head_ast)
    unindexed_languages = sorted({source.language for source in (*base_sources, *head_sources)
                                  if source.language not in ("c", "cpp")})
    impact = _dependent_closure(call_impact, base_reverse, head_reverse)
    unresolved = base_unresolved + head_unresolved
    inventory_incomplete = any(
        inventory.get("skipped") or any(item.get("status") == "partial"
                                         for item in inventory.get("source_archives", []))
        for inventory in (base_inventory, head_inventory)
    )
    include_status = "incomplete" if unresolved or inventory_incomplete else "tracked_quoted_includes_indexed"
    return {
        "schema_version": 1,
        "mode": "incremental_requested",
        "base_commit": base,
        "head_commit": head,
        "diff_status": "unavailable_full_fallback" if diff_error else "complete",
        "diff_error": diff_error,
        "changed_paths": scoped,
        "changed_path_count": len(scoped),
        "config_changed_paths": config_paths,
        "impact_paths": sorted(impact),
        "include_impact_paths": sorted(include_impact),
        "include_index": {
            "status": "incomplete" if base_load_error else include_status,
            "base_inventory_error": base_load_error,
            "base_dependency_edges": sum(len(value) for value in base_reverse.values()),
            "head_dependency_edges": sum(len(value) for value in head_reverse.values()),
            "unresolved_includes": unresolved[:100],
            "unresolved_include_count": len(unresolved),
            "external_angle_includes": len(base_external) + len(head_external),
            "truncated": len(unresolved) > 100,
        },
        "call_symbol_index": {
            "status": "incomplete" if call_unknown or ambiguous_symbols or truncated_calls or unindexed_languages else "conservative_syntax_candidates",
            "base_ast_files": len(base_ast), "head_ast_files": len(head_ast),
            "base_ast_indexing": base_index_metrics,
            "head_ast_indexing": head_index_metrics,
            "unindexed_languages": unindexed_languages,
            "candidate_edges": len(call_edges),
            "candidate_edge_examples": [
                {"definition_file": source, "caller_file": caller, "symbol": name}
                for source, caller, name in sorted(call_edges)[:100]
            ],
            "ambiguous_unqualified_symbols": ambiguous_symbols[:100],
            "unresolved_ast_or_names": call_unknown[:100],
            "truncated": len(call_unknown) > 100 or len(ambiguous_symbols) > 100 or truncated_calls,
            "reason": "C/C++ syntax names are candidates only; cross-language IPC/FFI edges, overload, namespace, macro, function pointer, virtual dispatch and build configuration remain unresolved",
        },
        "dependency_index": {"status": "incomplete", "reason": "detectors do not declare validated cross-file dependency inputs"},
        "reused_files": 0,
        "recomputed_files": None,
        "fallback": True,
        "fallback_reason": ("build_or_analysis_configuration_changed" if config_paths else
                            "git_diff_unavailable" if diff_error else
                            "base_dependency_inventory_unavailable" if base_load_error else
                            "dependency_index_incomplete_and_detector_reuse_not_proven"),
        "execution": "full_scan_required",
    }
