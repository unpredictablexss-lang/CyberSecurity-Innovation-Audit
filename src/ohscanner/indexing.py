"""M1 static source inventory on a pinned local Git commit. No vulnerability detection."""

import json
from importlib import metadata
from pathlib import Path
import platform
import subprocess

from .contracts import ScanContext, ScanRequest
from .fixture import snapshot_digest
from .facts import build_fact_view_v2, build_syntax_facts
from .frontend import index_sources
from .git_source import load_git_sources


def environment_fingerprint():
    """Reproduction information, not a guarantee of GN/product equivalence."""
    git = subprocess.run(
        ["git", "--version"], capture_output=True, text=True,
        check=True, timeout=5,
    ).stdout.strip()
    versions = {}
    for package in ("tree-sitter", "tree-sitter-c", "tree-sitter-cpp"):
        try:
            versions[package] = metadata.version(package)
        except metadata.PackageNotFoundError:
            versions[package] = "unavailable"
    return {
        "python": platform.python_version(),
        "git": git,
        "parsers": versions,
        "parse_profile": "light-ast",
        "build_profile": "none",
        "macro_expansion": False,
        "product_manifest_locked": False,
    }


def prepare_git_context(repo_dir: Path, repository: str, commit: str,
                        includes: tuple[str, ...] = (".",)):
    pinned, tree, sources, inventory = load_git_sources(repo_dir, commit, includes)
    units, ast, coverage = index_sources(sources)
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
            "facts_v1": build_syntax_facts(ast),
            "facts_v2": build_fact_view_v2(ast),
            "coverage": coverage,
            # Exact Git blob binding for A-CCR-03 occurrence records. The
            # identity layer records it; it never verifies repository ownership.
            "source_blob_oid": {source.path: source.oid for source in sources},
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
                "blob_oid": source.oid, "loc": len(u.text.splitlines()),
                "parse_status": u.parse_status, "parse_issues": list(u.parse_issues),
                "ast_functions": len(context.shared_facts["ast"].get(u.path, {}).get("functions", [])),
                "ast_calls": len(context.shared_facts["ast"].get(u.path, {}).get("calls", [])),
            } for u, source in zip(context.units, sources)
        ],
        "detector_runs": [],
        "candidate_count": 0,
        "validated_vulnerability": 0,
        "limitations": [
            "M1 indexes C/C++ syntax only; JS/TS/ArkTS receive no parsing/semantic analysis.",
            "Source repository name is user-declared; local Git object identity is checked, not official remote ownership.",
            "Headers default to C++ grammar; no GN/product compile flags, macro instantiation or full device coverage.",
            "No vulnerability detector executed. candidate_count=0 is not a security finding.",
            "Non-UTF8 and oversized sources are skipped and counted; report scope reflects actual selected files.",
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
