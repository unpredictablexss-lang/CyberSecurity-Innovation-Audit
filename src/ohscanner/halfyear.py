"""Bounded MVP for candidate detection over a half-year commit window.

This entry point is intentionally read-only with respect to Git: it selects
first-parent commits by committer time, diffs each selected commit against its
first parent, and scans only source paths present in that commit.  It never
fetches, checks out, builds, or promotes a candidate to a vulnerability.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence
from zoneinfo import ZoneInfo

from .contracts import safe_relative_path
from .detectors.catalog import build_registry
from .execution import run_fixed_commit_scan
from .git_source import SOURCE_LANGUAGES, _git

MVP_KIND = "ohscanner.halfyear-candidate-mvp-v1"
MAX_WINDOW_COMMITS = 5000
BRANCH_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_./-]{0,199}")


def _text(value: bytes) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("Git output is not UTF-8") from error


def _git_text(repo: Path, *args: str) -> str:
    return _text(_git(repo, *args))


def _validate_repo(repo: Path) -> Path:
    if repo.is_symlink() or not repo.is_dir():
        raise ValueError("source repository must be an existing non-symlink directory")
    return repo


def _parse_instant(value: str, timezone: str) -> int:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as error:
        raise ValueError("window timestamps must be ISO-8601") from error
    zone = ZoneInfo(timezone)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=zone)
    return int(parsed.timestamp())


def _branch_commit(repo: Path, branch: str) -> str:
    if (not BRANCH_PATTERN.fullmatch(branch) or ".." in branch
            or branch.startswith("-")):
        raise ValueError("invalid branch/ref for bounded window selection")
    return _git_text(repo, "rev-parse", "--verify", branch + "^{commit}").strip()


def _parent_of(repo: Path, commit: str) -> str | None:
    fields = _git_text(repo, "rev-list", "--parents", "-n", "1", commit).split()
    return fields[1] if len(fields) > 1 else None


def _blob_identity(repo: Path, revision: str, path: str) -> dict[str, Any]:
    """Read one exact tree entry and blob without checkout or lazy fetching."""
    raw = _git(repo, "ls-tree", "-z", revision, "--", path).split(b"\x00")
    rows = [item for item in raw if item]
    if not rows:
        return {"status": "absent"}
    if len(rows) != 1:
        raise ValueError("ambiguous Git tree entry for source path")
    try:
        metadata, path_bytes = rows[0].split(b"\t", 1)
        mode, kind, oid = metadata.decode("ascii").split()
        actual_path = safe_relative_path(path_bytes.decode("utf-8"))
    except (ValueError, UnicodeError) as error:
        raise ValueError("malformed Git tree entry") from error
    if actual_path != path:
        raise ValueError("Git tree path does not match requested source path")
    if kind != "blob" or mode == "160000":
        return {"status": "not_blob", "git_object_type": kind, "mode": mode}
    data = _git(repo, "cat-file", "blob", oid)
    return {
        "status": "bound",
        "revision": revision,
        "source_blob_oid": oid,
        "source_sha256": hashlib.sha256(data).hexdigest(),
        "source_bytes": len(data),
    }


def _tree_paths(repo: Path, commit: str) -> set[str]:
    raw = _git(repo, "ls-tree", "-z", "-r", commit).split(b"\x00")
    paths: set[str] = set()
    for item in raw:
        if not item:
            continue
        try:
            _metadata, path_bytes = item.split(b"\t", 1)
            paths.add(safe_relative_path(path_bytes.decode("utf-8")))
        except (ValueError, UnicodeError) as error:
            raise ValueError("malformed Git tree entry") from error
    return paths


def select_window(
    repo: Path,
    branch: str,
    start: str,
    end: str,
    timezone: str,
    *,
    max_commits: int = MAX_WINDOW_COMMITS,
) -> dict[str, Any]:
    """Select a half-open committer-time window on one first-parent history."""
    repo = _validate_repo(repo)
    if not 1 <= max_commits <= MAX_WINDOW_COMMITS:
        raise ValueError(f"max_commits must be 1..{MAX_WINDOW_COMMITS}")
    try:
        zone = ZoneInfo(timezone)
    except Exception as error:
        raise ValueError("unknown timezone: " + timezone) from error
    first, last = _parse_instant(start, timezone), _parse_instant(end, timezone)
    if first >= last:
        raise ValueError("date interval must be increasing and half-open [start,end)")
    tip = _branch_commit(repo, branch)
    rows: list[tuple[str, int]] = []
    raw = _git_text(repo, "log", "--first-parent", "--format=%H %ct", tip)
    for line in raw.splitlines():
        fields = line.split()
        if len(fields) != 2:
            raise ValueError("malformed git log output")
        rows.append((fields[0], int(fields[1])))
    selected = [
        (commit, stamp) for commit, stamp in rows if first <= stamp < last
    ]
    if len(selected) > max_commits:
        raise ValueError(
            "selected first-parent commit count exceeds max_commits="
            + str(max_commits)
        )
    selected_indices = [
        index for index, (_commit, stamp) in enumerate(rows)
        if first <= stamp < last
    ]
    if not selected_indices:
        raise ValueError("no commits selected in the requested date interval")
    low, high = min(selected_indices), max(selected_indices)
    endpoint = rows[low][0]
    oldest = rows[high][0]
    baseline = _parent_of(repo, oldest)
    if baseline is None:
        raise ValueError("earliest selected commit has no baseline parent")
    return {
        "tip": tip,
        "branch": branch,
        "baseline": baseline,
        "endpoint": endpoint,
        "oldest_selected": oldest,
        "selected_commits": [commit for commit, _stamp in selected],
        "selected_commit_meta": [
            {
                "commit": commit,
                "committer_time": datetime.fromtimestamp(stamp, tz=zone).isoformat(),
            }
            for commit, stamp in selected
        ],
        "intervening_outside_date": [
            commit for commit, _stamp in rows[low:high + 1]
            if commit not in {item[0] for item in selected}
        ],
        "time_basis": "committer",
        "timezone": timezone,
        "start": start,
        "end": end,
        "topology": "first-parent",
        "boundary": "[start,end)",
        "max_commits": max_commits,
        "selected_commit_count": len(selected),
        "selection_limit_status": "within_limit",
    }


def _diff_rows(repo: Path, baseline: str, endpoint: str) -> tuple[dict[str, str], ...]:
    raw = _git(
        repo, "diff", "--name-status", "-z", "--no-renames",
        baseline, endpoint, "--",
    ).split(b"\x00")
    rows: list[dict[str, str]] = []
    index = 0
    while index < len(raw) and raw[index]:
        if index + 1 >= len(raw):
            raise ValueError("invalid Git change list")
        status = _text(raw[index])
        path = safe_relative_path(_text(raw[index + 1]))
        if not status or status[0] not in "MADT":
            raise ValueError("unexpected diff status: " + status)
        rows.append({"status": status, "path": path})
        index += 2
    return tuple(rows)


def _source_path(path: str) -> bool:
    return SOURCE_LANGUAGES.get(Path(path).suffix.lower()) is not None


def _failure_kind(error: BaseException) -> str:
    text = f"{type(error).__name__}: {error}".lower()
    if any(marker in text for marker in (
        "missing_local_git_object", "missing_git_object",
        "missing object", "not a valid object", "bad object",
    )):
        return "missing_git_object"
    if "detector" in text:
        return "detector_execution"
    return "execution_error"


def _source_manifest(
    repo: Path,
    parent: str | None,
    commit: str,
    changes: Sequence[Mapping[str, str]],
    tree_paths: set[str],
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    rows: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for change in sorted(
        (item for item in changes if _source_path(item["path"])),
        key=lambda item: item["path"],
    ):
        path = change["path"]
        present = path in tree_paths
        revision = commit if present else parent
        row: dict[str, Any] = {
            "path": path,
            "diff_status": change["status"],
            "present_in_commit": present,
            "scan_eligible": False,
            "binding_revision": revision,
            "source_blob_oid": None,
            "source_sha256": None,
            "source_bytes": None,
            "binding_status": "unknown",
        }
        if revision is None:
            row["binding_status"] = "missing_baseline_parent"
            errors.append({"path": path, "reason": row["binding_status"]})
        else:
            try:
                identity = _blob_identity(repo, revision, path)
                identity_status = identity.pop("status", "unknown")
                row.update(identity)
                row["binding_revision"] = revision
                if identity_status == "bound":
                    row["binding_status"] = "bound"
                    row["scan_eligible"] = present
                else:
                    row["binding_status"] = identity_status
                    errors.append({"path": path, "reason": row["binding_status"]})
            except Exception as error:
                kind = _failure_kind(error)
                row["binding_status"] = kind
                row["error_type"] = type(error).__name__
                row["error"] = str(error)[:1000]
                errors.append({"path": path, "reason": kind})
        rows.append(row)
    return rows, errors


def _coverage_summary(report: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    coverage = report.get("detector_coverage", {}).get("detectors", {})
    result: dict[str, dict[str, Any]] = {}
    for detector, info in coverage.items():
        result[detector] = {
            "status": info.get("status", "unknown"),
            "applicable_files": info.get("applicable_files", 0),
            "analyzed_files": len(info.get("analyzed_files", [])),
            "partial_files": len(info.get("partially_inspected_files", [])),
            "not_analyzed_files": len(info.get("not_analyzed_files", [])),
            "coverage_counts": info.get("coverage_counts", {}),
            "source_sha256": info.get("source_sha256", {}),
            "unexamined": info.get("unexamined", []),
        }
    return result


def _source_observation_key(row: Mapping[str, Any]) -> str:
    payload = [
        row.get("detector_id"),
        row.get("rule_id"),
        row.get("file"),
        row.get("line"),
        row.get("column"),
        row.get("symbol") or "",
        row.get("source_sha256") or "",
    ]
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _candidate_rows(
    report: Mapping[str, Any],
    source_manifest: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    coverage = report.get("detector_coverage", {}).get("detectors", {})
    rows: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    manifest = {item["path"]: item for item in source_manifest}
    for run in report.get("detector_runs", []):
        detector = run.get("tool")
        info = coverage.get(detector, {})
        obligations: dict[str, Any] = {}
        for item in info.get("evidence_obligations", []):
            obligations[item.get("diagnostic_id")] = item.get("obligations", [])
        for diagnostic in run.get("diagnostics", []):
            identity = diagnostic.get("finding_identity") or {}
            observation = identity.get("observation") or {}
            binding = identity.get("source_binding") or {}
            file_path = diagnostic.get("file")
            expected = manifest.get(file_path, {})
            source_blob_oid = (
                diagnostic.get("source_blob_oid")
                or observation.get("source_blob_oid")
                or binding.get("source_blob_oid")
                or expected.get("source_blob_oid")
            )
            row = {
                "repository": report.get("repository"),
                "commit": report.get("commit"),
                "git_tree": report.get("git_tree"),
                "snapshot_sha256": report.get("snapshot_sha256"),
                "target_id": report.get("target_id"),
                "profile_id": report.get("profile_id"),
                "provenance": report.get("provenance"),
                "detector_id": detector,
                "detector_version": run.get("tool_version"),
                "detector_report_schema_version": run.get("schema_version"),
                "diagnostic_id": diagnostic.get("diagnostic_id"),
                "finding_identity_id": diagnostic.get("finding_identity_id"),
                "occurrence_id": diagnostic.get("occurrence_id"),
                "rule_id": diagnostic.get("rule_id"),
                "rule_version": diagnostic.get("rule_version") or observation.get("rule_version"),
                "rule_lineage_id": observation.get("rule_lineage_id"),
                "file": file_path,
                "line": diagnostic.get("line"),
                "column": diagnostic.get("column"),
                "symbol": diagnostic.get("symbol"),
                "symbol_identity": observation.get("symbol_identity"),
                "ast_fingerprint": observation.get("ast_fingerprint"),
                "identity_quality": observation.get("identity_quality"),
                "evidence_type": diagnostic.get("evidence_type"),
                "severity": diagnostic.get("severity"),
                "confidence": diagnostic.get("confidence"),
                "candidate_cwe": diagnostic.get("candidate_cwe"),
                "consequence_impact": diagnostic.get("consequence_impact"),
                "consequence_cwe": diagnostic.get("consequence_cwe"),
                "source_blob_oid": source_blob_oid,
                "source_sha256": diagnostic.get("source_sha256"),
                "byte_start": observation.get("byte_start"),
                "byte_end": observation.get("byte_end"),
                "message": diagnostic.get("message"),
                "evidence_level": "candidate/unassessed",
                "obligations": obligations.get(diagnostic.get("diagnostic_id"), []),
                "finding_identity": identity,
            }
            row["source_observation_key"] = _source_observation_key(row)
            reasons = []
            if run.get("schema_version") != 2:
                reasons.append("detector_report_not_schema_v2")
            if not expected:
                reasons.append("file_not_in_changed_source_manifest")
            if expected.get("binding_status") != "bound":
                reasons.append("source_manifest_not_bound")
            if row["source_sha256"] != expected.get("source_sha256"):
                reasons.append("source_sha256_mismatch")
            if source_blob_oid != expected.get("source_blob_oid"):
                reasons.append("source_blob_oid_mismatch")
            for key, actual in (
                ("repository", row["repository"]),
                ("commit", row["commit"]),
                ("snapshot_sha256", row["snapshot_sha256"]),
                ("profile_id", row["profile_id"]),
                ("detector_id", row["detector_id"]),
                ("detector_version", row["detector_version"]),
                ("rule_id", row["rule_id"]),
                ("file", row["file"]),
                ("source_sha256", row["source_sha256"]),
                ("source_blob_oid", row["source_blob_oid"]),
            ):
                declared = binding.get(key)
                if declared not in (None, "") and declared != actual:
                    reasons.append("source_binding_mismatch:" + key)
            if reasons:
                row["evidence_validity"] = "rejected_invalid_or_mixed"
                rejected.append({"candidate": row, "reasons": sorted(set(reasons))})
            else:
                row["evidence_validity"] = "accepted_source_bound_v2"
                rows.append(row)
    return rows, rejected


def _artifact(path: Path, root: Path | None = None) -> dict[str, Any]:
    data = path.read_bytes()
    return {
        "path": path.relative_to(root).as_posix() if root else path.name,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _scan_commit(
    repo: Path,
    repository: str,
    commit: str,
    parent: str | None,
    detector_ids: tuple[str, ...],
    commits_dir: Path,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "commit": commit,
        "parent": parent,
        "git_tree": None,
        "target_id": "current-component:" + repository,
        "profile_id": "light-ast",
        "provenance": "local_git_objects",
        "changed_paths": [],
        "changed_source_paths": [],
        "present_changed_source_paths": [],
        "deleted_changed_source_paths": [],
        "non_blob_changed_source_paths": [],
        "change_status": "unknown",
        "scan_status": "failed",
        "execution_status": "failed",
        "coverage_status": "unknown",
        "candidate_count_status": "unknown",
        "report_status": None,
        "candidate_count": None,
        "reported_candidate_observations": 0,
        "rejected_candidate_observations": 0,
        "coverage": {},
        "detector_runs": [],
        "source_manifest": [],
        "source_identity_errors": [],
        "candidates": [],
        "rejected_candidates": [],
        "artifacts": {},
        "limitations": [],
    }
    try:
        entry["git_tree"] = _git_text(repo, "rev-parse", commit + "^{tree}").strip()
        if parent is None:
            raise ValueError("missing_git_object: selected commit has no first parent")
        changes = _diff_rows(repo, parent, commit)
        changed_paths = [item["path"] for item in changes]
        source_paths = sorted({
            item["path"] for item in changes if _source_path(item["path"])
        })
        entry.update({
            "changed_paths": changed_paths,
            "changed_source_paths": source_paths,
        })
        tree_paths = _tree_paths(repo, commit)
        manifest, source_identity_errors = _source_manifest(
            repo, parent, commit, changes, tree_paths,
        )
        present = [item["path"] for item in manifest if item["scan_eligible"]]
        deleted = [
            item["path"] for item in manifest
            if not item["present_in_commit"] and item["diff_status"].startswith("D")
        ]
        non_blob = [
            item["path"] for item in manifest
            if item["present_in_commit"] and item["binding_status"] == "not_blob"
        ]
        entry.update({
            "present_changed_source_paths": present,
            "deleted_changed_source_paths": deleted,
            "non_blob_changed_source_paths": non_blob,
            "source_manifest": manifest,
            "source_identity_errors": source_identity_errors,
        })
        if not source_paths:
            entry.update({
                "change_status": "no_source_changes",
                "scan_status": "no_source_changes",
                "execution_status": "unexecuted",
                "coverage_status": "unexecuted",
                "candidate_count_status": "unexecuted_not_zero",
                "limitations": [
                    "No source path changed in this commit; no detector was executed "
                    "and candidate_count is unknown/not applicable, not zero."
                ],
            })
            return entry
        if not present:
            change_status = (
                "deleted_only_source_changes"
                if deleted else "not_scannable_source_changes"
            )
            entry.update({
                "change_status": change_status,
                "scan_status": change_status,
                "execution_status": "unexecuted",
                "coverage_status": "unexecuted",
                "candidate_count_status": "unexecuted_not_zero",
            })
            entry["limitations"].append(
                "Deleted or non-blob source changes were recorded but not scanned; "
                "candidate_count is unknown/not applicable, not zero."
            )
            return entry
        entry["change_status"] = "source_changes_present"
        json_out = commits_dir / (commit + ".json")
        md_out = commits_dir / (commit + ".md")
        report = run_fixed_commit_scan(
            repo_dir=repo,
            repository=repository,
            commit=commit,
            includes=tuple(present),
            detector_ids=detector_ids,
            json_out=json_out,
            md_out=md_out,
        )
        if (
            report.get("commit") != commit
            or report.get("repository") != repository
            or report.get("git_tree") != entry["git_tree"]
        ):
            raise ValueError("scan report commit does not match requested commit")
        rows, rejected = _candidate_rows(report, manifest)
        run_rows = []
        for run in report.get("detector_runs", []):
            run_rows.append({
                "detector_id": run.get("tool"),
                "detector_version": run.get("tool_version"),
                "schema_version": run.get("schema_version"),
                "status": run.get("status", "unknown"),
                "diagnostic_count": run.get("diagnostic_count"),
                "limitations": run.get("limitations", []),
            })
        coverage = _coverage_summary(report)
        run_states = [item["status"] for item in run_rows]
        coverage_states = [item["status"] for item in coverage.values()]
        if "failed" in run_states or "failed" in coverage_states:
            coverage_status = "failed"
        elif "blocked" in run_states or "blocked" in coverage_states:
            coverage_status = "blocked"
        elif (
            source_identity_errors or rejected
            or report.get("status") != "completed"
            or any(state != "complete" for state in coverage_states)
            or set(coverage) != {item["detector_id"] for item in run_rows}
        ):
            coverage_status = "partial"
        else:
            coverage_status = "complete"
        complete = (
            coverage_status == "complete"
            and not source_identity_errors
            and not rejected
            and all(item["schema_version"] == 2 for item in run_rows)
        )
        entry.update({
            "scan_status": "scanned",
            "execution_status": "completed",
            "coverage_status": coverage_status,
            "report_status": report.get("status"),
            "candidate_count": len(rows) if complete else None,
            "candidate_count_status": (
                "complete_count" if complete else coverage_status + "_unknown"
            ),
            "reported_candidate_observations": len(rows),
            "rejected_candidate_observations": len(rejected),
            "coverage": coverage,
            "detector_runs": run_rows,
            "candidates": rows,
            "rejected_candidates": rejected,
            "source_files": report.get("scope", {}).get("selected_source_files"),
            "source_bytes": report.get("scope", {}).get("selected_source_bytes"),
            "snapshot_sha256": report.get("snapshot_sha256"),
            "artifacts": {
                "report_json": _artifact(json_out, commits_dir.parent),
                "report_md": _artifact(md_out, commits_dir.parent),
            },
            "limitations": list(report.get("limitations", [])),
        })
        if not complete:
            entry["limitations"].append(
                "Candidate count is unknown for this commit because coverage or "
                "source binding is incomplete; reported observations are preserved "
                "separately and no safe/miss conclusion is issued."
            )
        return entry
    except Exception as error:
        failure_kind = _failure_kind(error)
        blocked = failure_kind == "missing_git_object"
        entry["scan_status"] = "blocked" if blocked else "failed"
        entry["execution_status"] = entry["scan_status"]
        entry["coverage_status"] = "blocked" if blocked else "failed"
        entry["candidate_count_status"] = (
            "unknown_blocked" if blocked else "unknown_failed"
        )
        entry["candidate_count"] = None
        entry["reported_candidate_observations"] = len(entry["candidates"])
        entry["failure_kind"] = failure_kind
        entry["error_type"] = type(error).__name__
        entry["error"] = str(error)[:2000]
        entry["limitations"].append(
            "This commit is blocked/unknown or failed; no zero candidate count, "
            "safe result, miss, or reportable conclusion is inferred from the failure."
        )
        return entry


def _render_markdown(report: Mapping[str, Any]) -> str:
    selection = report["window"]
    lines = [
        "# Half-year candidate detection MVP",
        "",
        "> Static candidate observations only; NOT validated vulnerabilities.",
        "",
        f"- Kind: `{report['kind']}`",
        f"- Repository: `{report['repository']}`",
        f"- Local path: `{report['repository_path']}`",
        f"- Branch/ref: `{selection['branch']}`",
        f"- Window: `{selection['start']}` to `{selection['end']}` "
        f"(`{selection['time_basis']}`, `{selection['topology']}`, `{selection['boundary']}`)",
        f"- Baseline: `{selection['baseline']}`",
        f"- Endpoint: `{selection['endpoint']}`",
        f"- Selected commits: {len(selection['selected_commits'])}",
        f"- Reported candidate observations: {report['totals']['reported_candidate_observations']}",
        f"- Candidate observations: {report['totals']['candidate_observations']}",
        f"- Distinct source-observation keys: {report['totals']['distinct_source_observation_keys']}",
        f"- Overall status: `{report['status']}`",
        f"- Validated vulnerabilities: {report['validated_vulnerability']}",
        "",
        "## Detectors",
        "",
        "| Detector | Version | Evidence level |",
        "|---|---|---|",
    ]
    for detector in report["detectors"]:
        lines.append(
            f"| `{detector['id']}` | {detector['version']} | {detector['evidence_level']} |"
        )
    lines.extend([
        "",
        "## Per-commit results",
        "",
        "| Commit | Committer time | Changed source | Execution | Coverage | Candidate count | Reported observations |",
        "|---|---|---:|---|---|---:|---:|",
    ])
    meta = {item["commit"]: item for item in selection["selected_commit_meta"]}
    for entry in report["commits"]:
        candidates = entry.get("candidate_count")
        lines.append(
            f"| `{entry['commit']}` | {meta.get(entry['commit'], {}).get('committer_time', '')} | "
            f"{len(entry.get('present_changed_source_paths', []))} | "
            f"{entry.get('execution_status')} | `{entry.get('coverage_status')}` | "
            f"{'unknown' if candidates is None else candidates} | "
            f"{entry.get('reported_candidate_observations', 0)} |"
        )
    lines.extend([
        "",
        "## Coverage",
        "",
        "| Commit | Detector | Coverage | Complete | Partial | Not analyzed |",
        "|---|---|---|---:|---:|---:|",
    ])
    for entry in report["commits"]:
        for detector, info in entry.get("coverage", {}).items():
            lines.append(
                f"| `{entry['commit']}` | `{detector}` | `{info.get('status')}` | "
                f"{info.get('analyzed_files', 0)} | {info.get('partial_files', 0)} | "
                f"{info.get('not_analyzed_files', 0)} |"
            )
    if report["candidates"]:
        lines.extend([
            "",
            "## Candidate rows",
            "",
            "| Commit | Detector | File:line | Rule | Source SHA-256 |",
            "|---|---|---|---|---|",
        ])
        for row in report["candidates"]:
            lines.append(
                f"| `{row['commit']}` | `{row['detector_id']}` | "
                f"`{row['file']}:{row['line']}` | `{row['rule_id']}` | "
                f"`{row['source_sha256']}` |"
            )
    else:
        lines.extend(["", "No candidate row was reported; this is not a safety result."])
    if report["rejected_candidates"]:
        lines.extend([
            "",
            "## Rejected mixed/invalid candidate evidence",
            "",
            f"{len(report['rejected_candidates'])} row(s) were rejected and are not "
            "included in candidate totals.",
        ])
    lines.extend(["", "## Limitations", ""])
    lines.extend("- " + item for item in report["limitations"])
    lines.append("")
    return "\n".join(lines)


def run_halfyear_candidate_mvp(
    repo_dir: Path,
    repository: str,
    branch: str,
    start: str,
    end: str,
    timezone: str,
    detector_ids: Sequence[str],
    out_dir: Path,
    *,
    max_commits: int = MAX_WINDOW_COMMITS,
    argv: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Run the bounded MVP and write JSON, Markdown, and a hash manifest."""
    repo = _validate_repo(Path(repo_dir))
    detectors = tuple(detector_ids)
    registry = build_registry(detectors)
    selection = select_window(
        repo, branch, start, end, timezone, max_commits=max_commits,
    )
    out = Path(out_dir).resolve()
    if out.exists():
        if not out.is_dir():
            raise ValueError("output path exists and is not a directory")
        if any(out.iterdir()):
            raise ValueError(
                "output directory must be absent or empty to preserve generated evidence"
            )
    else:
        out.mkdir(parents=True)
    commits_dir = out / "commits"
    commits_dir.mkdir()

    entries: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    rejected_candidates: list[dict[str, Any]] = []
    for item in selection["selected_commit_meta"]:
        parent = _parent_of(repo, item["commit"])
        entry = _scan_commit(
            repo, repository, item["commit"], parent, detectors, commits_dir,
        )
        entry["committer_time"] = item["committer_time"]
        entries.append(entry)
        candidates.extend(entry.get("candidates", []))
        rejected_candidates.extend(entry.get("rejected_candidates", []))

    try:
        range_changes = _diff_rows(repo, selection["baseline"], selection["endpoint"])
        range_change_status = "completed"
        range_change_error = None
    except Exception as error:
        range_changes = ()
        range_change_status = "blocked"
        range_change_error = f"{type(error).__name__}: {error}"[:2000]

    scanned = [entry for entry in entries if entry["execution_status"] == "completed"]
    blocked = [entry for entry in entries if entry["execution_status"] == "blocked"]
    failed = [entry for entry in entries if entry["execution_status"] == "failed"]
    source_change_entries = [
        entry for entry in entries if entry.get("changed_source_paths")
    ]
    if source_change_entries and all(
        entry["execution_status"] == "blocked" for entry in source_change_entries
    ):
        status = "blocked"
    elif source_change_entries and all(
        entry["execution_status"] == "failed" for entry in source_change_entries
    ):
        status = "failed"
    elif entries and all(entry["execution_status"] == "unexecuted" for entry in entries):
        status = "unexecuted"
    elif (
        blocked or failed or range_change_status == "blocked"
        or any(entry["coverage_status"] != "complete" for entry in scanned)
        or rejected_candidates
    ):
        status = "completed_with_limitations"
    else:
        status = "completed"

    by_detector = Counter(row["detector_id"] for row in candidates)
    detector_rows = [
        {
            "id": detector.detector_id,
            "version": detector.version,
            "model_version": getattr(detector, "model_version", None),
            "supported_languages": list(detector.supported_languages),
            "report_schema_version": 2,
            "evidence_level": "candidate/unassessed",
        }
        for detector in registry.detectors()
    ]
    execution_counts = Counter(entry["execution_status"] for entry in entries)
    change_counts = Counter(entry["change_status"] for entry in entries)
    coverage_counts = Counter(entry["coverage_status"] for entry in entries)
    failure_counts = Counter(
        entry.get("failure_kind") for entry in entries if entry.get("failure_kind")
    )
    source_identity_error_count = sum(
        len(entry.get("source_identity_errors", [])) for entry in entries
    )
    detector_blocked_commits = sum(
        any(item["status"] == "blocked" for item in entry.get("detector_runs", []))
        for entry in entries
    )
    source_manifest_rows = [
        item for entry in entries for item in entry.get("source_manifest", [])
    ]
    report: dict[str, Any] = {
        "schema_version": 2,
        "source_binding_schema_version": 2,
        "detector_diagnostic_schema_version": 2,
        "kind": MVP_KIND,
        "status": status,
        "repository": repository,
        "repository_path": str(repo),
        "target_id": "current-component:" + repository,
        "profile_id": "light-ast",
        "scope_profile": "changed-present-source-paths-per-commit",
        "provenance": "local_git_objects",
        "window": selection,
        "detectors": detector_rows,
        "offline_git": True,
        "git_access_policy": {
            "fetch": False,
            "checkout": False,
            "external_scanners": False,
            "lazy_fetch": False,
            "source": "local_pinned_git_objects",
        },
        "invocation": {
            "mode": "cli" if argv is not None else "programmatic",
            "argv": list(argv) if argv is not None else [],
            "argv_exact": argv is not None,
        },
        "diff_semantics": (
            "Each selected commit is compared with its first parent; only source paths "
            "present in that commit are scanned."
        ),
        "range_changes": {
            "status": range_change_status,
            "error": range_change_error,
            "changed_paths": [item["path"] for item in range_changes],
            "changed_source_paths": sorted({
                item["path"] for item in range_changes if _source_path(item["path"])
            }),
        },
        "commits": entries,
        "candidates": candidates,
        "rejected_candidates": rejected_candidates,
        "totals": {
            "selected_commits": len(entries),
            "scanned_commits": len(scanned),
            "blocked_commits": len(blocked),
            "failed_commits": len(failed),
            "unexecuted_commits": execution_counts.get("unexecuted", 0),
            "no_source_change_commits": change_counts.get("no_source_changes", 0),
            "no_present_changed_source_commits": (
                change_counts.get("deleted_only_source_changes", 0)
                + change_counts.get("not_scannable_source_changes", 0)
            ),
            "deleted_only_source_change_commits": (
                change_counts.get("deleted_only_source_changes", 0)
            ),
            "missing_git_object_commits": sum(
                entry.get("failure_kind") == "missing_git_object"
                or any(
                    item.get("reason") == "missing_git_object"
                    for item in entry.get("source_identity_errors", [])
                )
                for entry in entries
            ),
            "missing_git_object_source_entries": sum(
                item.get("reason") == "missing_git_object"
                for entry in entries
                for item in entry.get("source_identity_errors", [])
            ),
            "partial_coverage_commits": coverage_counts.get("partial", 0),
            "failed_coverage_commits": coverage_counts.get("failed", 0),
            "blocked_coverage_commits": coverage_counts.get("blocked", 0),
            "detector_blocked_commits": detector_blocked_commits,
            "source_identity_errors": source_identity_error_count,
            "source_manifest_entries": len(source_manifest_rows),
            "bound_source_manifest_entries": sum(
                item.get("binding_status") == "bound" for item in source_manifest_rows
            ),
            "reported_candidate_observations": len(candidates),
            "candidate_observations": len(candidates),
            "rejected_candidate_observations": len(rejected_candidates),
            "commits_with_complete_candidate_count": sum(
                entry["candidate_count"] is not None for entry in entries
            ),
            "commits_with_unknown_candidate_count": sum(
                entry["candidate_count"] is None for entry in entries
            ),
            "distinct_source_observation_keys": len({
                row["source_observation_key"] for row in candidates
            }),
            "candidate_observations_by_detector": dict(sorted(by_detector.items())),
            "candidate_count_scope": (
                "candidate_observations counts accepted reported rows only. A per-commit "
                "candidate_count is emitted only for complete source-bound coverage; "
                "blocked/failed/partial/unexecuted commits remain unknown, never zero."
            ),
            "execution_status_counts": dict(sorted(execution_counts.items())),
            "change_status_counts": dict(sorted(change_counts.items())),
            "coverage_status_counts": dict(sorted(coverage_counts.items())),
            "failure_kind_counts": dict(sorted(failure_counts.items())),
        },
        "candidate_status": "candidate/unassessed",
        "zero_result_interpretation": (
            "No accepted candidate rows is not safe, miss, confirmed, or reportable."
        ),
        "validated_vulnerability": 0,
        "confirmed": 0,
        "reportable": 0,
        "artifact_paths": {
            "json": "halfyear_candidates.json",
            "markdown": "halfyear_candidates.md",
            "manifest": "manifest.json",
        },
        "limitations": [
            "This MVP scans only changed source paths in a first-parent committer-time window.",
            "It does not scan unchanged files, deleted blobs, whole snapshots, builds, or dynamic behavior.",
            "Partial coverage, blocked commits, missing Git objects, and unsupported files remain unknown.",
            "A zero diagnostic count is not a safety result and does not establish Precision/Recall.",
            "Candidate rows are static observations, not confirmed vulnerabilities or independent root causes.",
            "No network fetch, checkout, external scanner, or untrusted build is performed by this MVP.",
        ],
    }
    json_path = out / "halfyear_candidates.json"
    md_path = out / "halfyear_candidates.md"
    json_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    md_path.write_text(_render_markdown(report), encoding="utf-8")
    files = {
        path.relative_to(out).as_posix(): _artifact(path, out)
        for path in sorted(out.rglob("*"))
        if path.is_file() and path.name != "manifest.json"
    }
    manifest = {
        "schema_version": 2,
        "kind": MVP_KIND + ".manifest",
        "source_binding_schema_version": 2,
        "report_sha256": files[json_path.relative_to(out).as_posix()]["sha256"],
        "markdown_sha256": files[md_path.relative_to(out).as_posix()]["sha256"],
        "files": files,
    }
    manifest_path = out / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report
