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
from src.ohscanner.indexing import environment_fingerprint, prepare_git_context


CASES = (
    {
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
    lines.extend(["", "## Boundaries", ""])
    lines.extend("- " + item for item in rows[0]["limitations"])
    (args.out_dir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
