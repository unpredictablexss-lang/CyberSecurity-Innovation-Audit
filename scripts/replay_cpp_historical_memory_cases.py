"""Replay first-party memory-safety detectors on pinned historical OpenHarmony cases.

The cases come from local Git objects and published benchmark manifests. The
script performs no fetch, checkout, build or external scanner invocation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.ohscanner.detectors.cpp.bounds_detector import CppBoundsDetector
from src.ohscanner.detectors.cpp.integer_bounds_detector import CppIntegerBoundsDetector
from src.ohscanner.detectors.cpp.null_dereference_detector import NullDereferenceDetector
from src.ohscanner.detectors.cpp.shared_ptr_race_detector import SharedPtrRaceDetector
from src.ohscanner.indexing import environment_fingerprint, prepare_git_context


CASES = (
    {
        "sample_id": "c_utils-singleton-uaf-2026-01",
        "cve": None,
        "repository": "openharmony/commonlibrary_c_utils",
        "repo_path": "/mnt/e/网安/_oh_targets/commonlibrary_c_utils",
        "vulnerable_commit": "bdfafdaafddb01ab7ae13354ce2ada9555d7935c",
        "fixed_commit": "9a3f281120307ec7dcce17fae882dcc4e6a6f4d7",
        "affected_files": ("base/include/singleton.h",),
        "detector": "ohscanner.cpp.shared_ptr_race",
        "expected": "possible_hit",
    },
    {
        "sample_id": "communication_dsoftbus_null_deref_001",
        "cve": "CVE-2025-26690",
        "repository": "openharmony/communication_dsoftbus",
        "repo_path": "/mnt/e/网安/_oh_targets/communication_dsoftbus",
        "vulnerable_commit": "258662cd9840b55a31546a72d91027f6368cea84",
        "fixed_commit": "192f3e11d74beeaa3d879333471deb8a24a7e1c5",
        "affected_files": ("core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp",),
        "detector": "ohscanner.cpp.null_dereference",
        "expected": "possible_hit",
    },
    {
        "sample_id": "arkcompiler_ets_runtime-atomic-index-overflow-2025-03",
        "cve": "CVE-2025-0587",
        "repository": "openharmony/arkcompiler_ets_runtime",
        "repo_path": "/mnt/e/网安/_oh_targets/arkcompiler_ets_runtime",
        "vulnerable_commit": "cae11f121c030a90ba41d8e4d866f91292f25892",
        "fixed_commit": "5aa9c035e98911ec7ed28065a2138c2709792a42",
        "affected_files": ("ecmascript/base/atomic_helper.cpp",),
        "detector": "ohscanner.cpp.integer_bounds",
        "expected": "possible_hit",
    },    {
        "sample_id": "arkcompiler_ets_runtime-jsarray-sort-oob-2025-02",
        "cve": "CVE-2025-23420",
        "repository": "openharmony/arkcompiler_ets_runtime",
        "repo_path": "/mnt/e/网安/_oh_targets/arkcompiler_ets_runtime",
        "vulnerable_commit": "aeee3fd12c03193545edea4b8e0fdfa3d9a03d11",
        "fixed_commit": "1b23531531e768398682582969c2a9f17e72cafe",
        "affected_files": ("ecmascript/js_array.cpp",),
        "detector": "ohscanner.cpp.bounds",
        "expected": "possible_hit",
    },
    {
        "sample_id": "kernel_liteos_a-getgroups-oob-2025-03",
        "cve": "CVE-2025-20042",
        "repository": "openharmony/kernel_liteos_a",
        "repo_path": "/mnt/e/网安/_wsl_targets_stage/kernel_liteos_a",
        "vulnerable_commit": "6ac8e246b0efd57a28ea05b6e6973ae0602fe032",
        "fixed_commit": "940a5a8c2cd1ced84d435933dbcdbb1a7fbf3000",
        "affected_files": ("syscall/process_syscall.c",),
        "detector": "ohscanner.cpp.bounds",
        "expected": "not_applicable",
    },
    {
        "sample_id": "kernel_liteos_a-os-copy-user-param-bypass-2025-03",
        "cve": "CVE-2025-21098",
        "repository": "openharmony/kernel_liteos_a",
        "repo_path": "/mnt/e/网安/_wsl_targets_stage/kernel_liteos_a",
        "vulnerable_commit": "f83c7205e7d685a999e5de360423c13db1886453",
        "fixed_commit": "e6eb21f55e4768f6cfbf09cedb0b35259bafcb4b",
        "affected_files": ("kernel/extended/dynload/src/los_exec_elf.c",),
        "detector": "not_applicable",
        "expected": "not_applicable",
    },
)


def _git(repo: str, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", repo, *args], stderr=subprocess.STDOUT)


def _revision(case: Dict[str, Any], kind: str) -> Dict[str, Any]:
    commit = case[f"{kind}_commit"]
    repo = case["repo_path"]
    tree = _git(repo, "rev-parse", f"{commit}^{{tree}}").decode().strip()
    files = []
    for path in case["affected_files"]:
        blob = _git(repo, "rev-parse", f"{commit}:{path}").decode().strip()
        data = _git(repo, "show", f"{commit}:{path}")
        files.append({
            "path": path,
            "blob_oid": blob,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        })
    return {"commit": commit, "git_tree": tree, "files": files}


def _run_case(case: Dict[str, Any]) -> Dict[str, Any]:
    vulnerable = _revision(case, "vulnerable")
    fixed = _revision(case, "fixed")
    patch = _git(
        case["repo_path"],
        "diff",
        case["vulnerable_commit"],
        case["fixed_commit"],
        "--",
        *case["affected_files"],
    )
    patch_sha256 = hashlib.sha256(patch).hexdigest()
    detector_id = case["detector"]
    if detector_id == "ohscanner.cpp.bounds":
        detector = CppBoundsDetector()
    elif detector_id == "ohscanner.cpp.integer_bounds":
        detector = CppIntegerBoundsDetector()
    elif detector_id == "ohscanner.cpp.shared_ptr_race":
        detector = SharedPtrRaceDetector()
    elif detector_id == "ohscanner.cpp.null_dereference":
        detector = NullDereferenceDetector()
    else:
        detector = None

    observations = []
    for kind, revision in (("vulnerable", vulnerable), ("fixed", fixed)):
        if detector is None:
            observations.append({
                "revision": kind,
                "status": "not_applicable",
                "candidate_count": None,
                "detector_status": "not_applicable",
                "findings": [],
            })
            continue
        context, tree, inventory, coverage, sources = prepare_git_context(
            Path(case["repo_path"]),
            case["repository"],
            revision["commit"],
            tuple(case["affected_files"]),
        )
        run = detector.detect(context, context.units)
        findings = [
            {
                "file": item.file,
                "line": item.line,
                "column": item.column,
                "rule_id": item.rule_id,
                "candidate_cwe": item.candidate_cwe,
                "symbol": item.symbol,
                "message": item.message,
                "source_sha256": item.source_sha256,
            }
            for item in run.findings
        ]
        raw_status = "possible_hit" if findings else "miss"
        observations.append({
            "revision": kind,
            "status": "not_applicable" if case["expected"] == "not_applicable" else raw_status,
            "raw_status": raw_status,
            "candidate_count": len(findings),
            "detector_status": run.status,
            "findings": findings,
        })
    return {
        "sample_id": case["sample_id"],
        "cve": case["cve"],
        "repository": case["repository"],
        "source_repo_path": case["repo_path"],
        "vulnerable": vulnerable,
        "fixed": fixed,
        "patch_sha256": patch_sha256,
        "detector_id": detector_id,
        "expected": case["expected"],
        "observations": observations,
        "limitations": [
            "Historical replay is a capability signal, not a new vulnerability claim.",
            "A possible_hit is not a confirmed product vulnerability; a miss is not a global detector recall claim.",
            "Kernel race and user/kernel boundary cases are not_applicable to the current bounds/integer lexical rules.",
        ],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    rows = [_run_case(case) for case in CASES]
    report = {
        "schema_version": 1,
        "experiment_kind": "a_memory_safety_historical_replay",
        "status": "completed_with_limitations",
        "cases": rows,
        "environment": environment_fingerprint(),
        "exact_argv": list(sys.argv),
    }
    (args.out_dir / "summary.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    applicable = [row for row in rows if row["expected"] == "possible_hit"]
    metrics = {
        "schema_version": 1,
        "eligible_historical_cases": len(applicable),
        "vulnerable_possible_hit": sum(row["observations"][0]["status"] == "possible_hit" for row in applicable),
        "fixed_miss": sum(row["observations"][1]["status"] == "miss" for row in applicable),
        "fixed_residual_candidate": sum(row["observations"][1]["status"] == "possible_hit" for row in applicable),
        "not_applicable_cases": sum(row["expected"] == "not_applicable" for row in rows),
        "precision_recall_eligible": False,
        "interpretation": "Small historical capability set only; these counts are not product Precision/Recall or global Recall.",
    }
    (args.out_dir / "metrics.json").write_text(
        json.dumps(metrics, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    lines = [
        "# A memory-safety historical replay", "",
        "> Capability signal only; no new vulnerability claim.", "",
        "| Sample | CVE | Vulnerable | Fixed | Detector |",
        "|---|---|---|---|---|",
    ]
    for row in rows:
        vuln = row["observations"][0]
        fixed = row["observations"][1]
        lines.append(
            f"| `{row['sample_id']}` | `{row['cve']}` | {vuln['status']} "
            f"({vuln['candidate_count']}) | {fixed['status']} "
            f"({fixed['candidate_count']}) | `{row['detector_id']}` |"
        )
    lines.extend([
        "",
        "## Historical capability counts",
        "",
        f"- Applicable historical cases: {metrics['eligible_historical_cases']}",
        f"- Vulnerable possible_hit: {metrics['vulnerable_possible_hit']}",
        f"- Fixed miss: {metrics['fixed_miss']}; fixed residual candidate: {metrics['fixed_residual_candidate']}",
        f"- Not-applicable cases: {metrics['not_applicable_cases']}",
        "",
        "These counts are not product Precision/Recall or global Recall.",
        "",
        "## Boundaries",
        "",
    ])
    lines.extend("- " + item for item in rows[0]["limitations"])
    (args.out_dir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
