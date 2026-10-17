"""Resumable manifest-driven community scan planning and offline execution."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

from .contracts import ScanContext, ScanRequest, SourceUnit, safe_relative_path
from .detectors.catalog import build_registry
from .fixture import snapshot_digest
from .runner import run_all_with_coverage


SOURCE_SUFFIXES = {
    ".c": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
    ".h": "cpp", ".hh": "cpp", ".hpp": "cpp",
    ".js": "js", ".ts": "ts", ".ets": "arkts",
}
_SHA1 = re.compile(r"[a-f0-9]{40}")
_SHA256 = re.compile(r"[a-f0-9]{64}")


def offline_git(repo: Path, *args: str, timeout: int = 60) -> bytes:
    env = os.environ.copy()
    env.update({
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_ALLOW_PROTOCOL": "",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
    })
    result = subprocess.run(
        ["git", "-c", "remote.origin.promisor=false", "-C", str(repo), *args],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, check=False, timeout=timeout,
    )
    if result.returncode:
        raise ValueError("offline git operation failed: " + result.stderr.decode("utf-8", "replace")[:300])
    return result.stdout


def git_blob_oid(data: bytes) -> str:
    header = b"blob " + str(len(data)).encode("ascii") + b"\x00"
    return hashlib.sha1(header + data).hexdigest()


def source_language(path: str) -> str | None:
    return SOURCE_SUFFIXES.get(Path(path).suffix.lower())


def _source_path(path: str) -> bool:
    return source_language(path) is not None


def _safe_manifest_path(value: str) -> str:
    return safe_relative_path(value)


def resolve_source_inventory(
    source_root: Path,
    repository: Mapping[str, Any],
    git_tree_rows: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Verify source-tar bytes against upstream Git tree blob identities."""
    if not source_root.is_dir() or source_root.is_symlink():
        raise ValueError("source root must be a real directory")
    rows = []
    for expected in sorted(git_tree_rows, key=lambda item: str(item["path"])):
        path = _safe_manifest_path(str(expected["path"]))
        if not _source_path(path):
            continue
        local = source_root / Path(*path.split("/"))
        if not local.is_file() or local.is_symlink():
            raise ValueError("source inventory file missing: " + path)
        data = local.read_bytes()
        oid = git_blob_oid(data)
        if oid != expected.get("blob_oid"):
            raise ValueError("source bytes do not match pinned Git blob: " + path)
        rows.append({
            "path": path,
            "blob_oid": oid,
            "source_sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
            "lines": len(data.splitlines()),
            "language": source_language(path),
        })
    if not rows:
        raise ValueError("repository source inventory is empty")
    return rows


def plan_repository_shards(
    *,
    repository: str,
    commit: str,
    tree: str,
    files: Sequence[Mapping[str, Any]],
    max_files: int = 1000,
    max_bytes: int = 16 * 1024 * 1024,
) -> dict[str, Any]:
    if max_files < 1 or max_bytes < 1:
        raise ValueError("invalid shard limits")
    if not _SHA1.fullmatch(commit) or not _SHA1.fullmatch(tree):
        raise ValueError("community plan requires full commit and tree IDs")
    shards: list[dict[str, Any]] = []
    current: list[dict[str, Any]] = []
    current_bytes = 0
    for row in sorted(files, key=lambda item: str(item["path"])):
        path = _safe_manifest_path(str(row["path"]))
        size = int(row["bytes"])
        if size < 0:
            raise ValueError("negative source size")
        if len(current) >= max_files or (current and current_bytes + size > max_bytes):
            shards.append(_finish_shard(len(shards), current))
            current, current_bytes = [], 0
        current.append(dict(row, path=path))
        current_bytes += size
    if current:
        shards.append(_finish_shard(len(shards), current))
    payload = {
        "schema_version": 1,
        "kind": "ohscanner.community-repository-plan.v1",
        "repository": repository,
        "commit": commit,
        "tree": tree,
        "policy": {
            "max_files_per_shard": max_files,
            "max_bytes_per_shard": max_bytes,
            "scan_mode": "offline_source_bound",
            "lazy_fetch": "forbidden",
        },
        "counts": {
            "files": len(files),
            "bytes": sum(int(row["bytes"]) for row in files),
            "shards": len(shards),
        },
        "shards": shards,
    }
    payload["plan_sha256"] = canonical_digest(payload)
    return payload


def _finish_shard(shard_id: int, rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    material = sorted(
        [(str(row["path"]), str(row["blob_oid"]), int(row["bytes"])) for row in rows]
    )
    digest = hashlib.sha256(json.dumps(material, separators=(",", ":")).encode("utf-8")).hexdigest()
    return {
        "shard_id": shard_id,
        "resume_key": f"{shard_id}:{digest}",
        "shard_sha256": digest,
        "files": len(rows),
        "bytes": sum(int(row["bytes"]) for row in rows),
        "paths": [str(row["path"]) for row in rows],
    }


def canonical_digest(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def load_source_units(
    source_root: Path,
    repository: str,
    commit: str,
    rows: Sequence[Mapping[str, Any]],
) -> tuple[ScanContext, dict[str, Any]]:
    from src.parser.ast import parse_source
    from .language import parse_script_text

    units: list[SourceUnit] = []
    ast_summary: dict[str, Any] = {}
    parse_counts: Counter[str] = Counter()
    total_loc = 0
    for row in sorted(rows, key=lambda item: str(item["path"])):
        path = _safe_manifest_path(str(row["path"]))
        local = source_root / Path(*path.split("/"))
        data = local.read_bytes()
        if git_blob_oid(data) != row["blob_oid"]:
            raise ValueError("source blob drift: " + path)
        if hashlib.sha256(data).hexdigest() != row["source_sha256"]:
            raise ValueError("source SHA-256 drift: " + path)
        text = data.decode("utf-8")
        language = source_language(path)
        if language is None:
            raise ValueError("unsupported source path: " + path)
        if language in ("c", "cpp"):
            index = parse_source(text, language=language)
            status = index.parse_status
            issues = tuple(str(item) for item in index.parse_issues)
            ast_summary[path] = {
                "parse_status": status,
                "functions": [item.__dict__ for item in index.functions],
                "calls": [item.__dict__ for item in index.calls],
                "variables": [item.__dict__ for item in index.variables],
            }
        else:
            index = parse_script_text(text, language)
            status = index["parse_status"]
            issues = tuple(str(item) for item in index["parse_issues"])
            ast_summary[path] = {
                "parse_status": status,
                "functions": index["functions"],
                "calls": index["calls"],
                "variables": index["variables"],
            }
        parse_counts[status] += 1
        total_loc += len(text.splitlines())
        units.append(SourceUnit(
            path=path, language=language, text=text,
            sha256=hashlib.sha256(data).hexdigest(),
            parse_status=status, parse_issues=issues,
        ))
    if not units:
        raise ValueError("scan shard has no source units")
    units_tuple = tuple(sorted(units, key=lambda item: item.path))
    request = ScanRequest(
        request_id="community:" + repository + ":" + commit[:12],
        repository=repository,
        commit=commit,
        snapshot_sha256=snapshot_digest(units_tuple),
        target_id="current-component:" + repository,
        profile_id="light-ast",
        provenance="git_object",
    )
    return ScanContext(request=request, units=units_tuple, shared_facts={"ast": ast_summary}), {
        "files": len(units_tuple),
        "loc": total_loc,
        "bytes": sum(len(unit.text.encode("utf-8")) for unit in units_tuple),
        "parse_counts": dict(sorted(parse_counts.items())),
    }


def scan_shard(
    *,
    source_root: Path,
    repository: str,
    commit: str,
    rows: Sequence[Mapping[str, Any]],
    detector_ids: Sequence[str],
) -> dict[str, Any]:
    started = time.perf_counter()
    context, coverage = load_source_units(source_root, repository, commit, rows)
    reports, sidecar = run_all_with_coverage(context, build_registry(detector_ids))
    elapsed = time.perf_counter() - started
    diagnostic_count = sum(report.diagnostic_count for report in reports)
    return {
        "schema_version": 1,
        "kind": "ohscanner.community-shard-result.v1",
        "identity": {
            "repository": repository,
            "commit": commit,
            "snapshot_sha256": context.request.snapshot_sha256,
            "source_paths": [unit.path for unit in context.units],
            "source_sha256": {unit.path: unit.sha256 for unit in context.units},
        },
        "coverage": coverage,
        "performance": {
            "wall_seconds": elapsed,
            "candidate_density_per_kloc": (
                diagnostic_count * 1000 / coverage["loc"] if coverage["loc"] else None
            ),
            "peak_rss_mb": _peak_rss_mb(),
            "io_read_bytes": _io_counter("read_bytes"),
            "io_write_bytes": _io_counter("write_bytes"),
        },
        "detector_reports": [report.to_dict() for report in reports],
        "coverage_sidecar": sidecar,
    }


def _peak_rss_mb() -> float | None:
    try:
        import resource
        value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return value / 1024 if os.name != "darwin" else value / (1024 * 1024)
    except Exception:
        return None


def _io_counter(name: str) -> int | None:
    try:
        for line in Path("/proc/self/io").read_text(encoding="ascii").splitlines():
            key, value = line.split(":", 1)
            if key == name:
                return int(value.strip())
    except Exception:
        return None
    return None


def select_first_parent_increment(
    repo: Path,
    endpoint: str,
    *,
    since: str,
    until: str,
) -> dict[str, Any]:
    raw = offline_git(
        repo, "log", "--first-parent", "--format=%H%x00%cI%x00%P%x00%s",
        endpoint,
    )
    commits = []
    patch_ids: dict[str, str] = {}
    duplicate_patch_ids: set[str] = set()
    for line in raw.decode("utf-8", "replace").splitlines():
        if not line:
            continue
        commit, committer_time, parents_text, subject = line.split("\x00", 3)
        if not _within_window(committer_time, since, until):
            continue
        parents = parents_text.split()
        changed = _changed_paths(repo, commit, parents)
        patch_id = None
        if len(parents) == 1:
            patch_id = _stable_patch_id(repo, commit, parents[0], changed)
            if patch_id in patch_ids:
                duplicate_patch_ids.add(patch_id)
            else:
                patch_ids[patch_id] = commit
        commits.append({
            "commit": commit,
            "committer_time": committer_time,
            "subject": subject,
            "parents": parents,
            "changed_paths": changed,
            "first_parent_diff": True,
            "stable_patch_id": patch_id,
            "duplicate_patch_id": patch_id in duplicate_patch_ids if patch_id else False,
        })
    for row in commits:
        if row["stable_patch_id"] in duplicate_patch_ids:
            row["duplicate_patch_id"] = True
    return {
        "schema_version": 1,
        "kind": "ohscanner.community-increment-selection.v1",
        "endpoint": endpoint,
        "since": since,
        "until": until,
        "selection": "first-parent history and each commit's first-parent diff",
        "counts": {
            "commits": len(commits),
            "non_merge": sum(len(row["parents"]) == 1 for row in commits),
            "merge": sum(len(row["parents"]) > 1 for row in commits),
            "duplicate_patch_ids": len(duplicate_patch_ids),
        },
        "commits": commits,
    }


def _parse_instant(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _within_window(value: str, since: str, until: str) -> bool:
    current = _parse_instant(value)
    return _parse_instant(since) <= current <= _parse_instant(until)

def _changed_paths(repo: Path, commit: str, parents: Sequence[str]) -> list[dict[str, str]]:
    base = parents[0] if parents else commit + "^{tree}"
    raw = offline_git(repo, "diff", "--no-renames", "--name-status", "-z", base, commit)
    parts = raw.split(b"\x00")
    rows = []
    for index in range(0, len(parts) - 1, 2):
        status = parts[index].decode("ascii").split("\t", 1)[0]
        path = _safe_manifest_path(parts[index + 1].decode("utf-8"))
        rows.append({"status": status, "path": path})
    return rows


def _stable_patch_id(
    repo: Path,
    commit: str,
    parent: str,
    changed: Sequence[Mapping[str, str]],
) -> str:
    source_paths = [row["path"] for row in changed if _source_path(str(row["path"]))]
    if not source_paths:
        return hashlib.sha256((commit + ":no-source-change").encode()).hexdigest()
    patch = offline_git(repo, "diff", "--no-ext-diff", "--no-renames", parent, commit, "--", *source_paths)
    result = subprocess.run(
        ["git", "patch-id", "--stable"], input=patch,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=60,
    )
    if result.returncode:
        raise ValueError("git patch-id failed")
    fields = result.stdout.decode().split()
    if len(fields) != 2 or not _SHA1.fullmatch(fields[0]):
        raise ValueError("invalid stable patch-id")
    return fields[0]
