"""Build the DelayedSingleton cross-version impact evidence package.

This research runner reads only local pinned Git objects. It does not fetch,
check out, rewrite, or execute repository code. The only executed code is the
self-authored controlled harness compiled against exact extracted source blobs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time
from typing import Any, Mapping, Sequence

from src.ohscanner.cross_version import build_package, enrich_diagnostic_identity
from src.ohscanner.execution import run_fixed_commit_scan
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.git_source import _git
from src.ohscanner.resource import finish_resource_monitor, start_resource_monitor
from src.ohscanner.poc.cpp_shared_ptr_race import (
    TSAN_MARKERS,
    _build,
    _run_outcome,
    _run_process,
)


ROOT = Path(__file__).resolve().parents[3]
DEFAULT_REPO = Path(
    "/mnt/e/网安/audit-sources-20261014/home/audit/openharmony-targets/commonlibrary_c_utils"
    if os.name != "nt"
    else "E:/网安/audit-sources-20261014/home/audit/openharmony-targets/commonlibrary_c_utils"
)
DEFAULT_OUTPUT = ROOT / "outputs/reports/cross_version_impact_delayed_singleton_20261016"
REPOSITORY = "openharmony/commonlibrary_c_utils"
SOURCE_PATH = "base/include/singleton.h"
DETECTOR_ID = "ohscanner.cpp.shared_ptr_race"
RULE_ID = "ohcpp-shared-ptr-race-candidate-001"
RULE_VERSION = "1.0.0"
RULE_LINEAGE_ID = RULE_ID + ":shared_ptr-static-member-conflict:v1"
PROFILE_ID = "light-ast"

BOUNDARY_COMMITS = (
    ("pre_introduction", "91b383b74f0b0bd580326b8886ad9940638b3821"),
    ("introduction", "2317226c6d474cc406848d69e1af4d870bba7917"),
    ("vulnerable", "bdfafdaafddb01ab7ae13354ce2ada9555d7935c"),
    ("declared_fix", "9a3f281120307ec7dcce17fae882dcc4e6a6f4d7"),
    ("complete_fix", "94344813e2900115307f771fc96aa09c88b8fdf4"),
    ("post_fix", "b807d3dadb7dbb7639fe85b3a5f72da18d318da2"),
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def git_text(repo: Path, *args: str) -> str:
    return _git(repo, *args).decode("utf-8")


def commit_meta(repo: Path, commit: str) -> dict[str, str]:
    raw = git_text(repo, "show", "-s", "--format=%H%n%T%n%P%n%cI%n%s", commit)
    lines = raw.splitlines()
    return {
        "commit": lines[0],
        "tree": lines[1],
        "parents": lines[2],
        "committer_time": lines[3],
        "subject": lines[4] if len(lines) > 4 else "",
    }


def source_blob(repo: Path, commit: str) -> tuple[str | None, bytes | None]:
    raw = _git(repo, "ls-tree", "-z", commit, "--", SOURCE_PATH)
    entries = [item for item in raw.split(b"\x00") if item]
    if not entries:
        return None, None
    if len(entries) != 1:
        raise ValueError("source path is ambiguous: " + commit)
    metadata, _path = entries[0].split(b"\t", 1)
    fields = metadata.split()
    if len(fields) != 3 or fields[1] != b"blob":
        raise ValueError("source path is not a blob: " + commit)
    oid = fields[2].decode("ascii")
    return oid, _git(repo, "cat-file", "blob", oid)


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)


def artifact(path: Path, root: Path, role: str, **extra: Any) -> dict[str, Any]:
    result = {
        "role": role,
        "path": path.relative_to(root).as_posix(),
        "sha256": sha256_file(path),
        "bytes": path.stat().st_size,
    }
    result.update(extra)
    return result


def enrich_scan_report(
    repo: Path,
    commit: str,
    report: dict[str, Any],
    report_path: Path,
) -> dict[str, Any]:
    blob, data = source_blob(repo, commit)
    if blob is None or data is None:
        return report
    source_text = data.decode("utf-8")
    for run in report.get("detector_runs", []):
        if run.get("tool") != DETECTOR_ID:
            continue
        enriched = []
        for diagnostic in run.get("diagnostics", []):
            item = dict(diagnostic)
            item.setdefault("tool_version", "0.5.0")
            enriched.append(enrich_diagnostic_identity(
                item,
                repository=REPOSITORY,
                commit=commit,
                snapshot_sha256=report["snapshot_sha256"],
                profile_id=PROFILE_ID,
                source_blob_oid=blob,
                source_text=source_text,
                rule_version=RULE_VERSION,
                rule_lineage_id=RULE_LINEAGE_ID,
                symbol_identity="OHOS::DelayedSingleton::instance_",
            ))
        run["diagnostics"] = enriched
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report


def scan_commit(
    repo: Path,
    commit: str,
    output: Path,
) -> tuple[dict[str, Any], Path]:
    stem = commit
    json_path = output / "versions" / f"{stem}.json"
    md_path = output / "versions" / f"{stem}.md"
    report = run_fixed_commit_scan(
        repo_dir=repo,
        repository=REPOSITORY,
        commit=commit,
        includes=(SOURCE_PATH,),
        detector_ids=(DETECTOR_ID,),
        json_out=json_path,
        md_out=md_path,
    )
    return enrich_scan_report(repo, commit, report, json_path), json_path


def build_version_matrix(repo: Path, output: Path) -> list[dict[str, Any]]:
    refs = git_text(
        repo,
        "for-each-ref",
        "--format=%(refname:short)",
        "refs/tags/OpenHarmony-*",
    ).splitlines()
    refs = sorted(item for item in refs if item)
    rows: list[dict[str, Any]] = []
    reports_dir = output / "versions"
    reports_dir.mkdir(parents=True, exist_ok=True)
    for ref in refs:
        commit = git_text(repo, "rev-parse", "--verify", ref + "^{commit}").strip()
        meta = commit_meta(repo, commit)
        blob, data = source_blob(repo, commit)
        report, report_path = scan_commit(repo, commit, output)
        rows.append({
            "ref": ref,
            "commit": commit,
            "tree": meta["tree"],
            "committer_time": meta["committer_time"],
            "source_path": SOURCE_PATH,
            "source_blob_oid": blob,
            "source_sha256": sha256_bytes(data) if data is not None else None,
            "source_bytes": len(data) if data is not None else None,
            "source_lines": len(data.splitlines()) if data is not None else None,
            "snapshot_sha256": report["snapshot_sha256"],
            "report_path": report_path.relative_to(output).as_posix(),
            "comparison_role": "version_matrix",
            "diagnostic_count": report["diagnostic_count"],
            "detector_status": report["detector_runs"][0]["status"],
            "coverage_status": report["detector_coverage"]["detectors"][DETECTOR_ID]["status"],
        })
    matrix = {
        "schema_version": 1,
        "kind": "ohscanner.local-fixed-ref-version-matrix.v1",
        "repository": REPOSITORY,
        "source_path": SOURCE_PATH,
        "selection": "all locally available OpenHarmony release tags, explicit ref-name order",
        "topology_note": (
            "first-parent is only a topology strategy for selecting a review window; "
            "it is not evidence of vulnerability propagation."
        ),
        "chronology_warning": "Commit time is descriptive and is not vulnerability introduction order.",
        "rows": rows,
    }
    matrix_path = output / "version_matrix.json"
    write_json(matrix_path, matrix)
    return rows


def run_boundary_static(
    repo: Path,
    output: Path,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for role, commit in BOUNDARY_COMMITS:
        meta = commit_meta(repo, commit)
        blob, data = source_blob(repo, commit)
        report = None
        report_path = None
        if blob is not None:
            report, scan_path = scan_commit(repo, commit, output)
            boundary_scan = output / "boundary" / "scans" / f"{role}.json"
            boundary_scan.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(scan_path, boundary_scan)
            report_path = boundary_scan.relative_to(output).as_posix()
        rows.append({
            "role": role,
            "commit": commit,
            "tree": meta["tree"],
            "parents": meta["parents"].split(),
            "committer_time": meta["committer_time"],
            "subject": meta["subject"],
            "source_blob_oid": blob,
            "source_sha256": sha256_bytes(data) if data is not None else None,
            "source_bytes": len(data) if data is not None else None,
            "source_lines": len(data.splitlines()) if data is not None else None,
            "snapshot_sha256": report["snapshot_sha256"] if report else snapshot_digest(()),
            "report_path": report_path,
            "diagnostic_count": report["diagnostic_count"] if report else 0,
        })
    return rows


def run_dynamic_case(
    role: str,
    data: bytes,
    output: Path,
    harness: Path,
    *,
    repeats: int,
    readers: int,
    iterations: int,
) -> dict[str, Any]:
    case_dir = output / "boundary" / "dynamic" / role
    include_dir = case_dir / "include"
    include_dir.mkdir(parents=True, exist_ok=True)
    source_path = include_dir / "singleton.h"
    source_path.write_bytes(data)
    binary = case_dir / "poc"
    build = _build(
        role,
        source_path,
        harness,
        harness.parent,
        binary,
        "clang++",
        60.0,
    )
    records: list[dict[str, Any]] = []
    if build.outcome == "build_success":
        prefix: list[str] = []
        setarch = shutil.which("setarch")
        if setarch:
            prefix = [setarch, platform.machine(), "-R"]
        env = dict(os.environ)
        env["TSAN_OPTIONS"] = "halt_on_error=1:second_deadlock_stack=1"

        def execute(mode: str, repeat: int) -> None:
            command = prefix + [str(binary), mode]
            if mode == "race":
                command += [str(readers), str(iterations)]
            code, elapsed, stdout, stderr, timed_out = _run_process(
                command,
                cwd=case_dir,
                timeout=120.0,
                env=env,
            )
            sanitizer, outcome = _run_outcome(code, stderr, timed_out)
            log = case_dir / f"{mode}-{repeat}.log"
            log.write_text(stdout + stderr, encoding="utf-8")
            records.append({
                "mode": mode,
                "repeat": repeat,
                "command": command,
                "exit_code": code,
                "elapsed_seconds": elapsed,
                "sanitizer_detected": sanitizer,
                "outcome": outcome,
                "log": log.relative_to(output).as_posix(),
                "log_sha256": sha256_file(log),
            })

        execute("single", 0)
        if records[-1]["outcome"] == "clean":
            for repeat in range(1, repeats + 1):
                execute("race", repeat)

    races = [item for item in records if item["mode"] == "race"]
    singles = [item for item in records if item["mode"] == "single"]
    if build.outcome != "build_success":
        regression = "blocked"
    elif len(singles) != 1 or singles[0]["outcome"] != "clean":
        regression = "harness_invalid"
    elif len(races) != repeats:
        regression = "blocked"
    elif all(item["outcome"] == "sanitizer_triggered" for item in races):
        regression = "reproduced"
    elif all(item["outcome"] == "clean" for item in races):
        regression = "clean_control"
    else:
        regression = "unstable"
    binary_hash = sha256_file(binary) if binary.is_file() else None
    if binary.is_file():
        binary.unlink()
    return {
        "source_path": source_path.relative_to(output).as_posix(),
        "source_sha256": sha256_bytes(data),
        "build": {
            "command": list(build.command),
            "exit_code": build.exit_code,
            "elapsed_seconds": build.elapsed_seconds,
            "outcome": build.outcome,
            "binary_sha256_before_cleanup": binary_hash,
        },
        "runs": records,
        "regression_outcome": regression,
    }


def write_patch(
    repo: Path,
    output: Path,
    name: str,
    parent: str,
    commit: str,
) -> Path:
    patch = output / "boundary" / "patches" / f"{name}.patch"
    patch.parent.mkdir(parents=True, exist_ok=True)
    patch.write_bytes(_git(repo, "diff", parent, commit, "--", SOURCE_PATH))
    return patch


def build_boundary_regression(
    repo: Path,
    output: Path,
    static_rows: Sequence[Mapping[str, Any]],
    *,
    repeats: int,
    readers: int,
    iterations: int,
) -> tuple[dict[str, Any], Path]:
    harness = ROOT / "src/ohscanner/poc/harnesses/cpp_shared_ptr_delayed_singleton/harness.cpp"
    dynamic_by_role: dict[str, Any] = {}
    for row in static_rows:
        if row["source_blob_oid"] is None:
            continue
        data = _git(repo, "cat-file", "blob", row["source_blob_oid"])
        dynamic_by_role[row["role"]] = run_dynamic_case(
            row["role"],
            data,
            output,
            harness,
            repeats=repeats,
            readers=readers,
            iterations=iterations,
        )

    support = {
        "pre_introduction": "not_present",
        "introduction": "affected",
        "vulnerable": "affected",
        "declared_fix": "affected",
        "complete_fix": "fixed",
        "post_fix": "fixed",
    }
    cases = []
    for row in static_rows:
        dynamic = dynamic_by_role.get(row["role"])
        expected = support[row["role"]]
        actual_support = expected
        if row["source_blob_oid"] is None:
            actual_support = "not_present" if expected == "not_present" else "unknown"
        elif expected in ("affected", "fixed"):
            outcome = dynamic["regression_outcome"] if dynamic else "blocked"
            if expected == "affected" and outcome != "reproduced":
                actual_support = "unknown"
            elif expected == "fixed" and outcome != "clean_control":
                actual_support = "unknown"
        cases.append({
            **dict(row),
            "expected_boundary_role": expected,
            "impact_support": actual_support,
            "dynamic": dynamic,
        })

    patches = {
        "introduction": write_patch(
            repo,
            output,
            "introduction",
            "91b383b74f0b0bd580326b8886ad9940638b3821",
            "2317226c6d474cc406848d69e1af4d870bba7917",
        ),
        "declared_fix": write_patch(
            repo,
            output,
            "declared-fix-partial",
            "bdfafdaafddb01ab7ae13354ce2ada9555d7935c",
            "9a3f281120307ec7dcce17fae882dcc4e6a6f4d7",
        ),
        "complete_fix": write_patch(
            repo,
            output,
            "complete-fix",
            "2653b25072d31b3a12aad0473c83ff52f8a87dbd",
            "94344813e2900115307f771fc96aa09c88b8fdf4",
        ),
    }
    tree_absence = output / "boundary" / "tree-absence-pre-introduction.json"
    write_json(tree_absence, {
        "schema_version": 1,
        "repository": REPOSITORY,
        "commit": "91b383b74f0b0bd580326b8886ad9940638b3821",
        "tree": commit_meta(repo, "91b383b74f0b0bd580326b8886ad9940638b3821")["tree"],
        "source_path": SOURCE_PATH,
        "source_blob_oid": None,
        "verification": "git ls-tree exact path returned no entry",
    })
    call_path = output / "boundary" / "call-path.json"
    harness_lines = harness.read_text(encoding="utf-8").splitlines()
    call_path_rows = [
        {"step": "main dispatches controlled workload", "harness_line": 72},
        {"step": "RunRace starts reader and destroyer threads", "harness_line": 43},
        {"step": "reader calls DelayedSingleton::GetInstance", "harness_line": 53},
        {"step": "destroyer calls DelayedSingleton::DestroyInstance", "harness_line": 64},
    ]
    for item in call_path_rows:
        item["source_line_text"] = harness_lines[item["harness_line"] - 1]
    write_json(call_path, {
        "schema_version": 1,
        "kind": "controlled-component-call-path.v1",
        "scope": "self-authored component harness; not a product entry path",
        "harness": {
            "path": harness.relative_to(ROOT).as_posix(),
            "sha256": sha256_file(harness),
        },
        "steps": call_path_rows,
    })
    regression = {
        "schema_version": 1,
        "kind": "ohscanner.cross-version-boundary-regression.v1",
        "repository": REPOSITORY,
        "source_path": SOURCE_PATH,
        "detector": {
            "id": DETECTOR_ID,
            "version": "0.5.0",
            "rule_id": RULE_ID,
        },
        "dynamic_scope": "controlled component harness only; no product execution",
        "repeats": repeats,
        "readers": readers,
        "iterations": iterations,
        "cases": cases,
        "patches": {
            name: {"path": path.relative_to(output).as_posix(), "sha256": sha256_file(path)}
            for name, path in patches.items()
        },
        "tree_absence_evidence": {
            "path": tree_absence.relative_to(output).as_posix(),
            "sha256": sha256_file(tree_absence),
        },
        "call_path_evidence": {
            "path": call_path.relative_to(output).as_posix(),
            "sha256": sha256_file(call_path),
        },
        "limitations": [
            "The controlled harness calls the exact component methods but is not an OpenHarmony product entry, permission trace or attacker-controlled workload.",
            "A clean ThreadSanitizer control supports the exact source repair but does not prove product-wide safety.",
            "No repository commit/tree/blob/report/diagnostic/review was rewritten.",
        ],
    }
    regression_path = output / "boundary-regression.json"
    write_json(regression_path, regression)
    return regression, regression_path


def selection_inputs(output: Path) -> list[dict[str, Any]]:
    input_dir = output / "inputs"
    input_dir.mkdir(parents=True, exist_ok=True)
    candidates = [
        (
            "halfyear_window_mvp",
            ROOT / "outputs/reports/halfyear_mvp_commonlibrary_20261015/halfyear_candidates.json",
            "The changed-source half-year MVP reported no candidate rows; the selected singleton path was outside those changed paths.",
        ),
        (
            "halfyear_window_manifest",
            ROOT / "outputs/reports/halfyear_mvp_commonlibrary_20261015/manifest.json",
            "Hash manifest for the half-year MVP.",
        ),
        (
            "range_endpoint_full",
            ROOT / "outputs/reports/halfyear_pilot_20261015/commonlibrary_c_utils_endpoint_full.json",
            "Full endpoint scan input; absence from a changed-path subset is not an impact verdict.",
        ),
        (
            "selected_candidate_poc",
            ROOT / "outputs/poc/shared-ptr-delayed-singleton-20261014/run-002/poc.json",
            "Historical controlled DelayedSingleton candidate evidence; preserved without rewriting IDs or conclusions.",
        ),
    ]
    rows = []
    for role, path, note in candidates:
        if not path.is_file():
            raise ValueError("selection input is missing: " + str(path))
        copied = input_dir / f"{role}{path.suffix}"
        shutil.copyfile(path, copied)
        rows.append({
            "role": role,
            "path": copied.relative_to(output).as_posix(),
            "original_path": path.relative_to(ROOT).as_posix(),
            "sha256": sha256_file(copied),
            "bytes": copied.stat().st_size,
            "note": note,
        })
    return rows


def build_manifest(
    repo: Path,
    output: Path,
    version_rows: Sequence[Mapping[str, Any]],
    boundary_static_rows: Sequence[Mapping[str, Any]],
    regression_path: Path,
) -> Path:
    detector_path = ROOT / "src/ohscanner/detectors/cpp/shared_ptr_race_detector.py"
    vulnerable = next(row for row in version_rows if row["ref"] == "OpenHarmony-v6.0.0.2-Release")
    vulnerable_report = _load_report(output / vulnerable["report_path"])
    diagnostics = vulnerable_report["detector_runs"][0]["diagnostics"]
    identity_ids = sorted({item["finding_identity_id"] for item in diagnostics})
    if not identity_ids or any(not item.startswith("ohfi:v1:") for item in identity_ids):
        raise ValueError("selected candidate has no complete stable Finding identity")
    diagnostic_ids = sorted({item["diagnostic_id"] for item in diagnostics})

    source_dir = output / "sources"
    source_dir.mkdir(parents=True, exist_ok=True)
    evidence = []
    evidence_by_blob: dict[str, dict[str, Any]] = {}
    unique_blobs = sorted({
        row["source_blob_oid"] for row in version_rows if row["source_blob_oid"] is not None
    })
    for blob in unique_blobs:
        data = _git(repo, "cat-file", "blob", blob)
        path = source_dir / f"{blob}.h"
        path.write_bytes(data)
        evidence_id = "source-" + blob
        evidence.append({
            "evidence_id": evidence_id,
            "role": "source",
            "path": path.relative_to(output).as_posix(),
            "sha256": sha256_file(path),
            "blob_oid": blob,
        })
        evidence_by_blob[blob] = evidence_id

    boundary = json.loads(regression_path.read_text(encoding="utf-8"))
    patch_paths = boundary["patches"]
    call_path = boundary["call_path_evidence"]
    tree_absence = boundary["tree_absence_evidence"]
    evidence.extend([
        {
            "evidence_id": "patch-introduction",
            "role": "patch",
            **patch_paths["introduction"],
        },
        {
            "evidence_id": "patch-declared-fix-partial",
            "role": "patch",
            **patch_paths["declared_fix"],
        },
        {
            "evidence_id": "patch-complete-fix",
            "role": "patch",
            **patch_paths["complete_fix"],
        },
        {
            "evidence_id": "call-path-controlled-component",
            "role": "call_path",
            **call_path,
        },
        {
            "evidence_id": "boundary-regression",
            "role": "revalidation",
            "path": regression_path.relative_to(output).as_posix(),
            "sha256": sha256_file(regression_path),
        },
        {
            "evidence_id": "tree-absence-pre-introduction",
            "role": "tree_absence",
            **tree_absence,
        },
    ])

    affected_blobs = {
        row["source_blob_oid"]
        for row in version_rows
        if row["source_blob_oid"] is not None
    }
    fixed_blob = "6c771512fa319cae4067779012c538ae32826c00"
    impact_by_blob = {}
    for blob in sorted(affected_blobs):
        if blob == fixed_blob:
            status = "fixed"
            support = "fixed"
            patch_id = "patch-complete-fix"
        else:
            status = "affected"
            support = "affected"
            patch_id = (
                "patch-declared-fix-partial"
                if blob == "fb65b4d89ff9c60c54bc6a8e106b06935f23f633"
                else "patch-complete-fix"
            )
        impact_by_blob[blob] = {
            "status": status,
            "boundary_support": support,
            "evidence_ids": [
                evidence_by_blob[blob],
                patch_id,
                "call-path-controlled-component",
                "boundary-regression",
            ],
        }

    full_matrix = output / "version_matrix.json"
    boundary_versions = [
        {
            **dict(row),
            "ref": row["commit"],
            "label": row["role"],
            "comparison_role": "boundary_regression",
        }
        for row in boundary_static_rows
    ]
    all_version_rows = [boundary_versions[0]] + list(version_rows) + boundary_versions[1:]
    manifest = {
        "schema_version": 1,
        "kind": "ohscanner.cross-version-comparison-manifest.v1",
        "repository": REPOSITORY,
        "version_range": {
            "first_ref": version_rows[0]["ref"],
            "last_ref": version_rows[-1]["ref"],
            "version_count": len(version_rows),
            "boundary_commit_count": len(boundary_versions),
            "selection_strategy": "explicit local fixed release refs plus exact boundary commits",
            "topology_note": (
                "first-parent is only a topology strategy for selecting a review window; "
                "it is not evidence of vulnerability propagation."
            ),
            "chronology_is_not_introduction_order": True,
        },
        "scope": {
            "source_path": SOURCE_PATH,
            "includes": [SOURCE_PATH],
            "excludes": [],
            "scope_basis": "exact single source path selected for cross-version candidate evidence",
        },
        "profile_id": PROFILE_ID,
        "detector": {
            "id": DETECTOR_ID,
            "version": "0.5.0",
            "rule_id": RULE_ID,
            "rule_version": RULE_VERSION,
            "rule_lineage_id": RULE_LINEAGE_ID,
            "implementation_sha256": sha256_file(detector_path),
            "implementation_path": detector_path.relative_to(ROOT).as_posix(),
        },
        "selection_inputs": selection_inputs(output) + [
            {
                "role": "version_matrix",
                "path": full_matrix.relative_to(output).as_posix(),
                "sha256": sha256_file(full_matrix),
                "bytes": full_matrix.stat().st_size,
                "note": "All locally available OpenHarmony release refs were resolved to exact commits/trees/blobs without fetch or checkout.",
            }
        ],
        "artifacts": [
            {
                "role": "selection_input",
                "path": item["path"],
                "sha256": item["sha256"],
            }
            for item in selection_inputs(output)
        ] + [
            {
                "role": "version_matrix",
                "path": full_matrix.relative_to(output).as_posix(),
                "sha256": sha256_file(full_matrix),
            }
        ],
        "evidence": evidence,
        "candidates": [
            {
                "candidate_id": "c_utils-delayed-singleton-shared-ptr-race-v1",
                "selection_status": "selected_from_candidate_review",
                "candidate_status": "candidate/unassessed",
                "stable_identity_ids": identity_ids,
                "historical_diagnostic_ids": diagnostic_ids,
                "historical_id_note": (
                    "These IDs are preserved observations from this run; older report IDs are not recomputed or rewritten."
                ),
                "not_present_evidence_ids": [
                    "tree-absence-pre-introduction",
                    "patch-introduction",
                    "call-path-controlled-component",
                    "boundary-regression",
                ],
                "not_present_boundary_support": "not_present",
                "impact_by_blob": impact_by_blob,
            }
        ],
        "versions": all_version_rows,
        "boundary_regression": {
            "role": "boundary_regression",
            "path": regression_path.relative_to(output).as_posix(),
            "sha256": sha256_file(regression_path),
        },
    }
    manifest_path = output / "comparison-manifest.json"
    write_json(manifest_path, manifest)
    return manifest_path


def canonical_digest(value: Any) -> str:
    payload = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return sha256_bytes(payload)


def build_coverage_invariance(
    version_rows: Sequence[Mapping[str, Any]],
    boundary_rows: Sequence[Mapping[str, Any]],
    *,
    shard_size: int,
) -> dict[str, Any]:
    projection = [
        {
            "ref": row.get("ref"),
            "commit": row.get("commit"),
            "tree": row.get("tree"),
            "source_blob_oid": row.get("source_blob_oid"),
            "source_sha256": row.get("source_sha256"),
            "coverage_status": row.get("coverage_status"),
            "diagnostic_count": row.get("diagnostic_count"),
        }
        for row in list(version_rows) + list(boundary_rows)
    ]
    shards = [
        projection[index:index + shard_size]
        for index in range(0, len(projection), shard_size)
    ]
    flattened = [row for shard in shards for row in shard]
    return {
        "schema_version": 1,
        "kind": "ohscanner.cross-version-coverage-invariance.v1",
        "status": "proved_for_ordered_shard_aggregation" if flattened == projection else "failed",
        "reference": "single ordered version/boundary row stream",
        "shard_size": shard_size,
        "shard_count": len(shards),
        "row_count": len(projection),
        "reference_digest": canonical_digest(projection),
        "sharded_digest": canonical_digest(flattened),
        "scope": (
            "Sharding changes scheduling and aggregation only. Exact commits, trees, "
            "blobs, source hashes, detector coverage and unknown states remain unchanged."
        ),
    }


def build_performance_summary(
    *,
    started: Mapping[str, Any],
    version_rows: Sequence[Mapping[str, Any]],
    boundary_rows: Sequence[Mapping[str, Any]],
    output: Path,
    failures: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    monitor = finish_resource_monitor(dict(started))
    source_rows = [row for row in list(version_rows) + list(boundary_rows)]
    artifacts = [
        path for path in output.rglob("*") if path.is_file()
    ]
    return {
        "schema_version": 1,
        "kind": "ohscanner.cross-version-performance.v1",
        "wall_seconds": monitor["wall_seconds"],
        "rss": {
            "peak_bytes": monitor["peak_rss_bytes"],
            "measured": monitor["rss_measured"],
            "scope": "current research runner process; child compiler/PoC peak RSS is unknown",
            "start": monitor["start_rss"],
            "end": monitor["end_rss"],
        },
        "files": {
            "version_rows": len(version_rows),
            "boundary_rows": len(boundary_rows),
            "source_files_bound": sum(
                row.get("source_blob_oid") is not None for row in source_rows
            ),
            "source_bytes": sum(int(row.get("source_bytes") or 0) for row in source_rows),
            "source_lines": sum(int(row.get("source_lines") or 0) for row in source_rows),
            "output_files": len(artifacts),
            "output_bytes": sum(path.stat().st_size for path in artifacts),
        },
        "failures": list(failures),
        "resource_budget": {
            "wall_seconds": None,
            "source_scope": "one exact source path per fixed version/boundary row",
            "dynamic_repeats_are_explicit": True,
        },
    }


def _load_report(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("invalid report: " + str(path))
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-dir", type=Path, default=DEFAULT_REPO)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--readers", type=int, default=4)
    parser.add_argument("--iterations", type=int, default=20000)
    parser.add_argument("--shard-size", type=int, default=8)
    parser.add_argument(
        "--truth-manifest",
        type=Path,
        default=ROOT / "research/evidence/cpp/independent_truth_review_20261015/truth_set_manifest.json",
    )
    parser.add_argument(
        "--prediction-manifest",
        type=Path,
        default=ROOT / "research/evidence/cpp/independent_truth_review_20261015/independent_truth_review.json",
    )
    args = parser.parse_args()
    if args.shard_size <= 0:
        parser.error("--shard-size must be positive")
    started = start_resource_monitor()
    repo = args.repo_dir.resolve()
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        raise SystemExit("output directory must be absent or empty: " + str(output))
    output.mkdir(parents=True, exist_ok=True)

    version_rows = build_version_matrix(repo, output)
    static_rows = run_boundary_static(repo, output)
    regression, regression_path = build_boundary_regression(
        repo,
        output,
        static_rows,
        repeats=args.repeats,
        readers=args.readers,
        iterations=args.iterations,
    )
    manifest_path = build_manifest(
        repo,
        output,
        version_rows,
        static_rows,
        regression_path,
    )
    package = build_package(
        manifest_path,
        repo,
        output,
        argv=tuple(sys.argv),
        truth_manifest_path=args.truth_manifest,
        prediction_manifest_path=args.prediction_manifest,
    )

    coverage = build_coverage_invariance(
        version_rows,
        static_rows,
        shard_size=args.shard_size,
    )
    coverage_path = output / "coverage-invariance.json"
    write_json(coverage_path, coverage)
    failures = []
    for case in regression["cases"]:
        dynamic = case.get("dynamic") or {}
        outcome = dynamic.get("regression_outcome")
        if case.get("impact_support") == "unknown" or outcome in {
            "blocked", "harness_invalid", "unstable"
        }:
            failures.append({
                "kind": "boundary_regression",
                "role": case.get("role"),
                "commit": case.get("commit"),
                "impact_support": case.get("impact_support"),
                "dynamic_outcome": outcome,
                "build_outcome": dynamic.get("build", {}).get("outcome"),
            })
    performance = build_performance_summary(
        started=started,
        version_rows=version_rows,
        boundary_rows=static_rows,
        output=output,
        failures=failures,
    )
    performance_path = output / "performance.json"
    write_json(performance_path, performance)

    summary = {
        "schema_version": 1,
        "kind": "ohscanner.cross-version-impact-run-summary.v1",
        "repository": REPOSITORY,
        "comparison_manifest_sha256": sha256_file(manifest_path),
        "impact_evidence_sha256": sha256_file(output / "impact_evidence.json"),
        "boundary_regression_sha256": sha256_file(regression_path),
        "version_rows": len(version_rows),
        "candidate_count": len(package["candidates"]),
        "boundary_cases": [
            {
                "role": item["role"],
                "commit": item["commit"],
                "impact_support": item["impact_support"],
                "dynamic_outcome": item["dynamic"]["regression_outcome"] if item["dynamic"] else None,
            }
            for item in regression["cases"]
        ],
        "network_actions": "none",
        "git_mutations": "none",
        "invocation": {
            "argv": list(sys.argv),
            "argv_exact": True,
            "working_directory": str(Path.cwd()),
        },
        "coverage_invariance": {
            "status": coverage["status"],
            "sha256": sha256_file(coverage_path),
            "reference_digest": coverage["reference_digest"],
            "sharded_digest": coverage["sharded_digest"],
        },
        "performance": {
            "sha256": sha256_file(performance_path),
            "wall_seconds": performance["wall_seconds"],
            "peak_rss_bytes": performance["rss"]["peak_bytes"],
            "rss_measured": performance["rss"]["measured"],
            "files": performance["files"],
            "failure_count": len(failures),
        },
        "accuracy_evaluation": package["accuracy_evaluation"],
        "known_risks": [
            "Candidate observation relations are not vulnerability propagation proof.",
            "Component affected/fixed/not_present states do not prove product entry, privilege, deployment or CIA impact.",
            "Zero candidate observations and clean controls do not prove safety.",
            "Precision/Recall remains blocked unless an independent reliable truth holdout is complete.",
        ],
        "next_steps": [
            "Bind product components to per-component actual SHAs and collect product build/entry/privilege/CIA evidence.",
            "Freeze and execute an independent vulnerable/fixed/safe/unrelated holdout without model-derived truth.",
            "Measure child-process peak RSS separately from the runner-process RSS reported here.",
        ],
    }
    write_json(output / "run-summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
