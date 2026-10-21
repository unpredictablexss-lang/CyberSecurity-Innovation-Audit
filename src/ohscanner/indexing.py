"""M1 static source inventory on a pinned local Git commit. No vulnerability detection."""

import json
from importlib import metadata
from pathlib import Path
import platform
import subprocess
from time import perf_counter, process_time

from .contracts import ScanContext, ScanRequest
from .fixture import snapshot_digest
from .fact_providers import DEFAULT_FACT_PROVIDERS
from .frontend import index_sources
from .git_source import load_git_sources


def child_cpu_seconds():
    """Cumulative reaped-child CPU seconds, or None where resource is unavailable."""
    try:
        import resource
        usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        return usage.ru_utime + usage.ru_stime
    except (ImportError, AttributeError, OSError):
        return None


def _parse_cpu_max(value: str):
    """Parse cgroup v2 cpu.max without guessing from host logical CPUs."""
    fields = value.split()
    if len(fields) != 2:
        return None
    quota, period = fields
    if period.isdecimal() and int(period) > 0 and quota == "max":
        return {"cores": None, "status": "unlimited"}
    if not quota.isdecimal() or not period.isdecimal() or int(period) <= 0:
        return None
    return {"cores": int(quota) / int(period), "status": "limited"}


def _parse_cpu_v1(quota: str, period: str):
    """Parse cgroup v1 CFS quota files."""
    try:
        quota_value, period_value = int(quota.strip()), int(period.strip())
    except (TypeError, ValueError):
        return None
    if quota_value == -1 and period_value > 0:
        return {"cores": None, "status": "unlimited"}
    if quota_value <= 0 or period_value <= 0:
        return None
    return {"cores": quota_value / period_value, "status": "limited"}


def _effective_cpu_quota(values, source):
    limited = [item["cores"] for item in values
               if item is not None and item["status"] == "limited"]
    if limited:
        return {"cores": min(limited), "status": "limited", "source": source}
    if any(item is not None and item["status"] == "unlimited" for item in values):
        return {"cores": None, "status": "unlimited", "source": source}
    return None


def cpu_quota_info():
    """Return an enforced cgroup CPU quota, or explicit unknown/unlimited status."""
    try:
        memberships = Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines()
    except OSError:
        memberships = []

    for line in memberships:
        fields = line.split(":", 2)
        if len(fields) != 3:
            continue
        _, controllers, group = fields
        relative = Path(group.lstrip("/"))
        directories = [Path("/sys/fs/cgroup") / Path(*relative.parts[:depth])
                       for depth in range(len(relative.parts), -1, -1)]
        if not controllers:
            parsed_values = []
            for directory in directories:
                try:
                    parsed_values.append(_parse_cpu_max(
                        (directory / "cpu.max").read_text(encoding="ascii")))
                except OSError:
                    continue
            effective = _effective_cpu_quota(parsed_values, "cgroup v2 cpu.max hierarchy")
            if effective is not None:
                return effective
        elif "cpu" in controllers.split(","):
            parsed_values = []
            directories = [Path("/sys/fs/cgroup/cpu") / Path(*relative.parts[:depth])
                           for depth in range(len(relative.parts), -1, -1)]
            for base in directories:
                try:
                    parsed_values.append(_parse_cpu_v1(
                        (base / "cpu.cfs_quota_us").read_text(encoding="ascii"),
                        (base / "cpu.cfs_period_us").read_text(encoding="ascii"),
                    ))
                except OSError:
                    continue
            effective = _effective_cpu_quota(parsed_values, "cgroup v1 CFS quota hierarchy")
            if effective is not None:
                return effective
    return {"cores": None, "status": "unknown", "source": None}


def environment_fingerprint():
    """Reproduction information, not a guarantee of GN/product equivalence."""
    git = subprocess.run(
        ["git", "--version"], capture_output=True, text=True,
        check=True, timeout=5,
    ).stdout.strip()
    versions = {}
    for package in ("tree-sitter", "tree-sitter-c", "tree-sitter-cpp",
                    "tree-sitter-javascript", "tree-sitter-typescript"):
        try:
            versions[package] = metadata.version(package)
        except metadata.PackageNotFoundError:
            versions[package] = "unavailable"
    quota = cpu_quota_info()
    return {
        "python": platform.python_version(),
        "git": git,
        "parsers": versions,
        "parse_profile": "light-ast",
        "build_profile": "none",
        "macro_expansion": False,
        "product_manifest_locked": False,
        "cpu_quota_cores": quota["cores"],
        "cpu_quota_status": quota["status"],
        "cpu_quota_source": quota["source"],
    }


def prepare_git_context(repo_dir: Path, repository: str, commit: str,
                        includes: tuple[str, ...] = (".",), *, ast_cache=None,
                        phase_metrics=None, requested_facts=("facts_v1",)):
    source_started = perf_counter()
    source_cpu_started = process_time()
    child_cpu_before = child_cpu_seconds()
    pinned, tree, sources, inventory = load_git_sources(repo_dir, commit, includes)
    source_seconds = perf_counter() - source_started
    source_cpu_seconds = process_time() - source_cpu_started
    child_cpu_after = child_cpu_seconds()
    parse_metrics = {}
    units, ast, coverage = index_sources(sources, ast_cache=ast_cache, metrics=parse_metrics)
    fact_values, missing_facts, fact_metrics = DEFAULT_FACT_PROVIDERS.build(
        ast, requested_facts, (unit.language for unit in units))
    if phase_metrics is not None:
        phase_metrics["source_read_seconds"] = phase_metrics.get("source_read_seconds", 0.0) + source_seconds
        phase_metrics["source_read_cpu_seconds"] = phase_metrics.get("source_read_cpu_seconds", 0.0) + source_cpu_seconds
        phase_metrics["source_read_child_cpu_seconds"] = (
            phase_metrics.get("source_read_child_cpu_seconds", 0.0)
            + (child_cpu_after - child_cpu_before)
            if child_cpu_before is not None and child_cpu_after is not None else None
        )
        phase_metrics["ast_parse_seconds"] = parse_metrics["parse_seconds"]
        phase_metrics["ast_parse_cpu_seconds"] = parse_metrics["parse_cpu_seconds"]
        phase_metrics["frontend_seconds"] = parse_metrics["frontend_seconds"]
        phase_metrics["frontend_cpu_seconds"] = parse_metrics["frontend_cpu_seconds"]
        phase_metrics["facts_build_seconds"] = fact_metrics["provider_wall_seconds"]
        phase_metrics["facts_build_cpu_seconds"] = fact_metrics["provider_cpu_seconds"]
        phase_metrics["fact_providers"] = fact_metrics["providers"]
        phase_metrics["missing_facts"] = list(missing_facts)
        phase_metrics["parse_files"] = parse_metrics["parse_files"]
        phase_metrics["indexed_files"] = parse_metrics["indexed_files"]
        phase_metrics["ast_cache"] = parse_metrics["cache"]
    digest = snapshot_digest(units)
    context = ScanContext(
        request=ScanRequest(
            request_id="git-index:" + pinned[:12] + ":" + digest[:12],
            repository=repository, commit=pinned, snapshot_sha256=digest,
            target_id="current-component:" + repository,
            profile_id="light-ast", provenance="git_object",
        ),
        units=units,
        shared_facts={
            "ast": ast,
            "source_blob_oid": {item.path: item.oid for item in sources if item.archive_binding is None},
            "source_archive_binding": {item.path: item.archive_binding for item in sources if item.archive_binding is not None},
            **fact_values,
            "coverage": coverage,
        },
    )
    return context, tree, inventory, coverage, sources


def run_git_index(repo_dir: Path, repository: str, commit: str,
                  includes: tuple[str, ...], json_out: Path, md_out: Path):
    """Read pinned objects twice (before and after parsing) to detect drift."""
    if json_out.resolve() == md_out.resolve():
        raise ValueError("JSON and Markdown paths must differ")
    context, tree, inventory, coverage, sources = prepare_git_context(
        repo_dir, repository, commit, includes
    )
    commit2, tree2, sources2, inventory2 = load_git_sources(
        repo_dir, commit, includes
    )
    if (commit2 != context.request.commit or tree != tree2
            or tuple((s.path, s.oid, s.data) for s in sources)
               != tuple((s.path, s.oid, s.data) for s in sources2)
            or inventory2 != inventory):
        raise ValueError("pinned Git object inventory changed during analysis")
    report = {
        "schema_version": 1,
        "experiment_kind": "current_component_source_index",
        "status": "index_only",
        "repository": context.request.repository,
        "commit": context.request.commit,
        "target_id": context.request.target_id,
        "git_tree": tree,
        "snapshot_sha256": context.request.snapshot_sha256,
        "provenance": "local_git_objects",
        "profile_id": "light-ast",
        "environment": environment_fingerprint(),
        "scope": inventory,
        "coverage": coverage,
        "source_units": [
            {
                "file": u.path, "language": u.language, "sha256": u.sha256,
                "blob_oid": source.oid if source.archive_binding is None else None,
                "archive_binding": source.archive_binding,
                "loc": len(u.text.splitlines()),
                "parse_status": u.parse_status, "parse_issues": list(u.parse_issues),
                "ast_functions": len(context.shared_facts["ast"].get(u.path, {}).get("functions", [])),
                "ast_calls": len(context.shared_facts["ast"].get(u.path, {}).get("calls", [])),
            } for u, source in zip(context.units, sources)
        ],
        "detector_runs": [],
        "candidate_count": 0,
        "validated_vulnerability": 0,
        "limitations": [
            "C/C++ and JS/TS syntax are bounded; unsupported ArkTS remains partial/unknown, without type/manifest semantics.",
            "Source repository name is user-declared; local Git object identity is checked, not official remote ownership.",
            "Headers default to C++ grammar; no GN/product compile flags, macro instantiation or full device coverage.",
            "No vulnerability detector executed. candidate_count=0 is not a security finding.",
            "Non-UTF8 and oversized sources are skipped and counted; report scope reflects actual selected files.",
            "Tracked tar.gz/tgz archives are read-only and bounded; archive member paths are virtual and bind to archive Git blob plus archive/member SHA-256.",
        ],
    }
    md = [
        "# OHScanner M1 Fixed-Commit Source Index", "",
        "> Source/AST inventory, NOT a vulnerability report.", "",
        f"- Repository (user declared): `{repository}`",
        f"- Commit: `{commit}`", f"- Git tree: `{tree}`",
        f"- Source manifest SHA-256: `{context.request.snapshot_sha256}`",
        f"- Profile: `light-ast`",
        f"- Python: `{report['environment']['python']}`",
        f"- Git: `{report['environment']['git']}`",
        f"- Scanned source files: **{inventory['selected_source_files']}**",
        f"- Tracked Git entries: {inventory['tracked_entries']}",
        f"- Out of scope: {inventory['out_of_scope']}",
        f"- Unsupported/non-source entries: {inventory['non_source']}",
        f"- Git symlinks ignored: {inventory['symlinks']}",
        f"- Submodules ignored: {inventory['submodules']}",
        f"- Oversize/non-UTF8 skipped: {inventory['oversize']}/{inventory['binary_or_non_utf8']}",
        f"- Languages: `{json.dumps(coverage['languages'], sort_keys=True)}`",
        f"- Parse statuses: `{json.dumps(coverage['parsing_status'], sort_keys=True)}`",
        "",
        "## Unsupported and unknown coverage", "",
    ]
    md += ["- " + limit for limit in report["limitations"]]
    md += ["", "## Per-file index", "",
           "| Path | Language | Parse | Functions | Calls |",
           "|---|---|---|---:|---:|"]
    for item in report["source_units"]:
        md.append(
            f"| `{item['file']}` | {item['language']} | {item['parse_status']} | "
            f"{item['ast_functions']} | {item['ast_calls']} |"
        )
    # First create the output only after successfully reading and rechecking sources.
    json_out.parent.mkdir(parents=True, exist_ok=True)
    md_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    md_out.write_text("\n".join(md) + "\n", encoding="utf-8")
    return report
