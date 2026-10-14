#!/usr/bin/env python3
"""Validate and replay the A-line five-component same-scope scan.

The manifests are explicit pinned scope plans. This script does not invent scope:
it verifies every path and plan digest against the pinned Git tree before it runs
the existing ohscan-run command. It therefore cannot silently replace a missing
historical scope with a nearby scope.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path, PureWindowsPath
from typing import Any, Iterable


COMPONENTS = (
    "update_updateservice",
    "security_access_token",
    "distributeddatamgr_kv_store",
    "window_window_manager",
    "communication_dsoftbus",
)
EXPECTED_COUNTS = {
    "update_updateservice": (219, 217),
    "security_access_token": (550, 539),
    "distributeddatamgr_kv_store": (1446, 1439),
    "window_window_manager": (1112, 1079),
    "communication_dsoftbus": (1656, 1025),
}
DETECTORS = ("ohscanner.cpp.shared_ptr_race", "ohscanner.cpp.lifetime")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ValidationError(ValueError):
    """A scope or source preflight failed closed."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def shard_digest(entries: Iterable[tuple[str, str]]) -> str:
    digest = hashlib.sha256()
    for path, oid in entries:
        digest.update((path + ":" + oid + "\n").encode("utf-8"))
    return digest.hexdigest()


def plan_digest(commit: str, shard_digests: Iterable[str]) -> str:
    digest = hashlib.sha256()
    digest.update(("plan:" + commit + "\n").encode("utf-8"))
    for value in shard_digests:
        digest.update((value + "\n").encode("utf-8"))
    return digest.hexdigest()


def resolve_repo_path(raw: str) -> Path:
    """Resolve manifest paths on Windows or under WSL without changing them."""
    if re.match(r"^[A-Za-z]:[\\/]", raw) and os.name != "nt":
        drive = raw[0].lower()
        rest = raw[2:].replace("\\", "/")
        return Path("/mnt") / drive / rest.lstrip("/")
    return Path(raw)


def _tree_entries(repo: Path, commit: str) -> dict[str, tuple[str, int]]:
    if not repo.is_dir() or repo.is_symlink():
        raise ValidationError(f"source repository is missing or a symlink: {repo}")
    try:
        raw = subprocess.run(
            ["git", "-C", str(repo), "ls-tree", "-r", "-z", "-l", commit],
            check=True,
            capture_output=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValidationError(f"cannot read pinned tree for {repo}: {exc}") from exc

    result: dict[str, tuple[str, int]] = {}
    for item in raw.split(b"\0"):
        if not item:
            continue
        header, path_bytes = item.split(b"\t", 1)
        parts = header.split()
        if len(parts) != 4:
            raise ValidationError(f"unexpected git ls-tree row: {item!r}")
        mode, kind, oid, size_text = parts
        path = path_bytes.decode("utf-8")
        if kind != b"blob":
            continue
        if path in result:
            raise ValidationError(f"duplicate tree path: {path}")
        size = -1 if size_text == b"-" else int(size_text)
        result[path] = (oid.decode("ascii"), size)
    return result


def _validate_relative_path(path: Any) -> str:
    if not isinstance(path, str) or not path or path.startswith("/") or "\\" in path:
        raise ValidationError(f"invalid relative source path: {path!r}")
    if ".." in PureWindowsPath(path).parts:
        raise ValidationError(f"path traversal is not allowed: {path}")
    return path


def validate_manifest_data(manifest: dict[str, Any], tree: dict[str, tuple[str, int]], expected_counts: dict[str, tuple[int, int]] | None = None) -> dict[str, Any]:
    for key in ("component", "repository", "source_repo_path", "commit", "git_tree", "counts", "plan_sha256", "shards"):
        if key not in manifest:
            raise ValidationError(f"manifest missing {key}")
    if not SHA_RE.fullmatch(manifest["commit"]):
        raise ValidationError("commit must be a full lowercase SHA-1")
    if not SHA_RE.fullmatch(manifest["git_tree"]):
        raise ValidationError("git_tree must be a full lowercase SHA-1")
    if not SHA256_RE.fullmatch(manifest["plan_sha256"]):
        raise ValidationError("plan_sha256 must be SHA-256")
    expected_selected, expected_applicable = (expected_counts or EXPECTED_COUNTS)[manifest["component"]]
    counts = manifest["counts"]
    shards = manifest["shards"]
    if counts.get("selected_files") != expected_selected:
        raise ValidationError(f"{manifest['component']}: selected_files must be {expected_selected}")
    if counts.get("shards") != len(shards):
        raise ValidationError(f"{manifest['component']}: shard count mismatch")
    if not shards:
        raise ValidationError(f"{manifest['component']}: no shards")

    all_paths: list[str] = []
    shard_digests: list[str] = []
    selected_bytes = 0
    for expected_id, shard in enumerate(shards):
        if shard.get("shard_id") != expected_id:
            raise ValidationError(f"{manifest['component']}: shard IDs must be contiguous")
        paths = shard.get("paths")
        if not isinstance(paths, list) or not paths:
            raise ValidationError(f"{manifest['component']}: shard {expected_id} has no paths")
        normalized = [_validate_relative_path(path) for path in paths]
        if normalized != sorted(normalized):
            raise ValidationError(f"{manifest['component']}: shard {expected_id} paths are not sorted")
        entries: list[tuple[str, str]] = []
        for path in normalized:
            if path not in tree:
                raise ValidationError(f"{manifest['component']}: path is absent from pinned tree: {path}")
            oid, size = tree[path]
            entries.append((path, oid))
            selected_bytes += size
        all_paths.extend(normalized)
        computed_shard = shard_digest(entries)
        if shard.get("shard_sha256") != computed_shard:
            raise ValidationError(f"{manifest['component']}: shard {expected_id} digest mismatch")
        shard_digests.append(computed_shard)

    if len(all_paths) != len(set(all_paths)):
        raise ValidationError(f"{manifest['component']}: duplicate paths across shards")
    if all_paths != sorted(all_paths):
        raise ValidationError(f"{manifest['component']}: concatenated shards are not globally sorted")
    if counts.get("selected_bytes") != selected_bytes:
        raise ValidationError(f"{manifest['component']}: selected_bytes mismatch")
    if len(all_paths) != expected_selected:
        raise ValidationError(f"{manifest['component']}: expected {expected_selected} selected paths")
    computed_plan = plan_digest(manifest["commit"], shard_digests)
    if manifest["plan_sha256"] != computed_plan:
        raise ValidationError(f"{manifest['component']}: plan digest mismatch")
    return {
        "component": manifest["component"],
        "selected_files": len(all_paths),
        "selected_bytes": selected_bytes,
        "applicable_files": expected_applicable,
        "shards": len(shards),
        "plan_sha256": computed_plan,
        "scope_equivalent": True,
    }


def validate_manifest(path: Path) -> dict[str, Any]:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    repo = resolve_repo_path(manifest["source_repo_path"])
    tree = _tree_entries(repo, manifest["commit"])
    actual_tree = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", f"{manifest['commit']}^{{tree}}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if actual_tree != manifest["git_tree"]:
        raise ValidationError(f"{manifest['component']}: git tree mismatch")
    result = validate_manifest_data(manifest, tree)
    result.update(
        {
            "manifest": str(path),
            "manifest_sha256": sha256_file(path),
            "repository": manifest["repository"],
            "commit": manifest["commit"],
            "git_tree": manifest["git_tree"],
            "source_repo_path": str(repo),
        }
    )
    return result


def _baseline_rows(path: Path) -> dict[str, dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    rows = data.get("a_shared_ptr_component_runs", [])
    return {row["component"]: row for row in rows}


def verify_baseline_hashes(
    baseline_summary: Path,
    baseline_dir: Path | None,
) -> dict[str, Any]:
    rows = _baseline_rows(baseline_summary)
    result: dict[str, Any] = {"status": "unknown", "components": {}}
    if baseline_dir is None:
        result["reason"] = "no baseline artifact directory supplied"
        return result
    all_found = True
    for component, row in rows.items():
        item: dict[str, Any] = {
            "expected_json_sha256": row.get("json_sha256"),
            "expected_md_sha256": row.get("md_sha256"),
        }
        json_path = baseline_dir / f"{component}.json"
        md_path = baseline_dir / f"{component}.md"
        for key, expected, artifact in (
            ("json", row.get("json_sha256"), json_path),
            ("md", row.get("md_sha256"), md_path),
        ):
            if not artifact.is_file():
                item[key] = {"status": "missing", "path": str(artifact)}
                all_found = False
                continue
            actual = sha256_file(artifact)
            item[key] = {
                "status": "match" if actual == expected else "mismatch",
                "actual_sha256": actual,
                "path": str(artifact),
            }
            all_found = all_found and actual == expected
        result["components"][component] = item
    result["status"] = "verified" if all_found else "missing_or_mismatch"
    return result


def _report_projection(report: dict[str, Any]) -> dict[str, Any]:
    runs = []
    for run in report.get("detector_runs", []):
        runs.append(
            {
                "tool": run.get("tool"),
                "tool_version": run.get("tool_version"),
                "status": run.get("status"),
                "scope_files": run.get("scope_files"),
                "diagnostics": run.get("diagnostic_count"),
                "limitations": len(run.get("limitations", [])),
            }
        )
    coverage = report.get("detector_coverage", {}).get("detectors", {})
    coverage_rows = {}
    for detector, item in coverage.items():
        counts = item.get("coverage_counts", {})
        coverage_rows[detector] = {
            "status": item.get("status"),
            "coverage_counts": counts,
            "source_sha256_count": len(item.get("source_sha256", {})),
            "evidence_obligations": len(item.get("evidence_obligations", [])),
        }
    return {
        "repository": report.get("repository"),
        "commit": report.get("commit"),
        "git_tree": report.get("git_tree"),
        "snapshot_sha256": report.get("snapshot_sha256"),
        "status": report.get("status"),
        "validated_vulnerability": report.get("validated_vulnerability"),
        "selected_source_files": report.get("scope", {}).get("selected_source_files"),
        "detector_runs": runs,
        "coverage": coverage_rows,
        "diagnostic_count": report.get("diagnostic_count"),
    }


def _run_component(
    project_root: Path,
    manifest_path: Path,
    out_dir: Path,
    baseline_rows: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    component = manifest["component"]
    repo = resolve_repo_path(manifest["source_repo_path"])
    json_out = out_dir / f"{component}.json"
    md_out = out_dir / f"{component}.md"
    terminal_out = out_dir / f"{component}.terminal.txt"
    command_out = out_dir / f"{component}.command.json"
    command = [
        sys.executable,
        "-m",
        "src.cli",
        "ohscan-run",
        "--repo-dir",
        str(repo),
        "--repository",
        manifest["repository"],
        "--commit",
        manifest["commit"],
    ]
    for shard in manifest["shards"]:
        for path in shard["paths"]:
            command.extend(("--include", path))
    for detector in DETECTORS:
        command.extend(("--detector", detector))
    command.extend(("--json-out", str(json_out), "--md-out", str(md_out)))
    started = time.perf_counter()
    done = subprocess.run(command, cwd=project_root, text=True, capture_output=True)
    elapsed = time.perf_counter() - started
    terminal_out.write_text(done.stdout + done.stderr, encoding="utf-8")
    command_out.write_text(
        json.dumps({"command": command, "cwd": str(project_root), "returncode": done.returncode}, indent=2) + "\n",
        encoding="utf-8",
    )
    if done.returncode:
        raise RuntimeError(f"{component}: ohscan-run failed: {done.stderr[-2000:]}")
    report = json.loads(json_out.read_text(encoding="utf-8"))
    row = baseline_rows.get(component, {})
    return {
        "component": component,
        "manifest_sha256": sha256_file(manifest_path),
        "source_repo_path": str(repo),
        "report": _report_projection(report),
        "artifacts": {
            "json": {"path": str(json_out), "sha256": sha256_file(json_out)},
            "md": {"path": str(md_out), "sha256": sha256_file(md_out)},
            "terminal": {"path": str(terminal_out), "sha256": sha256_file(terminal_out)},
            "command": {"path": str(command_out), "sha256": sha256_file(command_out)},
        },
        "old_shared_ptr_candidates": row.get("candidate_diagnostics"),
        "old_json_sha256": row.get("json_sha256"),
        "old_md_sha256": row.get("md_sha256"),
        "candidate_comparison": {
            "status": "unknown",
            "reason": "historical A-line report bytes are not available in this checkout; counts remain directional only",
        },
        "elapsed_seconds": round(elapsed, 3),
    }


def render_summary(summary: dict[str, Any]) -> str:
    lines = [
        "# A 线固定五组件同范围复扫",
        "",
        f"- 生成时间：{summary['generated']}",
        f"- 范围校验：{summary['scope_validation']['status']}",
        f"- 历史结果哈希核验：{summary['baseline_hash_verification']['status']}",
        f"- validated_vulnerability：{summary['validated_vulnerability']}",
        "",
        "## 组件结果",
        "",
        "| 组件 | 范围文件 | shared_ptr 候选 | lifetime 候选 | Detector 状态 |",
        "|---|---:|---:|---:|---|",
    ]
    for row in summary["components"]:
        runs = {item["tool"]: item for item in row["report"]["detector_runs"]}
        shared = runs.get("ohscanner.cpp.shared_ptr_race", {}).get("diagnostics", "unknown")
        lifetime = runs.get("ohscanner.cpp.lifetime", {}).get("diagnostics", "unknown")
        states = ", ".join(f"{item['tool']}={item['status']}" for item in row["report"]["detector_runs"])
        lines.append(f"| {row['component']} | {row['report']['selected_source_files']} | {shared} | {lifetime} | {states} |")
    lines.extend(
        [
            "",
            "## 边界",
            "",
            "- 文件解析 partial/not_analyzed 仍是 unknown，不是 safe 或 miss。",
            "- 历史 A 报告字节未在当前 checkout 中找到，因此旧候选集合比较保持 unknown。",
            "- 本次不改变候选 ID、历史报告、漏洞等级或公共契约；不计算 Precision/Recall。",
        ]
    )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--manifest-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--baseline-summary", type=Path, required=True)
    parser.add_argument("--baseline-dir", type=Path, default=None)
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args(argv)

    project_root = args.project_root.resolve()
    manifest_dir = args.manifest_dir.resolve()
    out_dir = args.out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    manifests = [manifest_dir / f"{component}.manifest.json" for component in COMPONENTS]
    if any(not path.is_file() for path in manifests):
        missing = [str(path) for path in manifests if not path.is_file()]
        raise ValidationError("missing scope manifests: " + ", ".join(missing))
    scope_rows = [validate_manifest(path) for path in manifests]
    scope_validation = {
        "status": "verified",
        "manifests": scope_rows,
        "expected_counts": {key: list(value) for key, value in EXPECTED_COUNTS.items()},
    }
    baseline_hash_verification = verify_baseline_hashes(args.baseline_summary, args.baseline_dir)
    if args.preflight_only:
        summary = {
            "schema_version": 1,
            "kind": "cpp_same_scope_preflight",
            "generated": "2026-10-14 Asia/Shanghai",
            "scope_validation": scope_validation,
            "baseline_hash_verification": baseline_hash_verification,
            "validated_vulnerability": 0,
            "components": [],
        }
        (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        (out_dir / "summary.md").write_text(render_summary(summary), encoding="utf-8")
        return 0

    baseline_rows = _baseline_rows(args.baseline_summary)
    components = [_run_component(project_root, path, out_dir, baseline_rows) for path in manifests]
    summary = {
        "schema_version": 1,
        "kind": "cpp_same_scope_rescan_summary",
        "generated": "2026-10-14 Asia/Shanghai",
        "scope_validation": scope_validation,
        "baseline_hash_verification": baseline_hash_verification,
        "validated_vulnerability": 0,
        "components": components,
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (out_dir / "summary.md").write_text(render_summary(summary), encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValidationError, RuntimeError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
