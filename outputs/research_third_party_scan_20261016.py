#!/usr/bin/env python3
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, "/mnt/e/网安/CyberSecurity-Innovation-Audit")

from src.ohscanner.detectors.catalog import build_registry
from src.ohscanner.detectors.cpp.m2_adapter import M2LifetimeDetector, M2SharedPtrRaceDetector
from src.ohscanner.detectors.cpp.null_dereference_detector import NullDereferenceDetector
from src.ohscanner.detectors.interface.m2_adapter import M2IpcInterfaceDetector
from src.ohscanner.execution import run_reviewed_detectors
from src.ohscanner.runner import DetectorRegistry

PROJECT = Path("/mnt/e/网安/CyberSecurity-Innovation-Audit")
ROOT = Path("/mnt/e/网安/_third_party_targets_20261016")
OUT_ROOT = PROJECT / "outputs/reports/third_party_high_risk_20261016"

TARGETS = {
    "third_party_cJSON": {
        "repository": "openharmony/third_party_cJSON",
        "commit": "0c2c9dff82cc85539c8362132d7a5f6bf7d1e748",
        "includes": ["cJSON.c", "cJSON.h", "cJSON_Utils.c", "cJSON_Utils.h"],
    },
    "third_party_curl": {
        "repository": "openharmony/third_party_curl",
        "commit": "1386bb128bb060b284309397b97adcaaec21c003",
        "includes": ["lib", "include"],
    },
    "third_party_sqlite": {
        "repository": "openharmony/third_party_sqlite",
        "commit": "34478e73d5a6d22237edacea92b331fb76127982",
        "includes": ["src", "include"],
    },
    "third_party_zlib": {
        "repository": "openharmony/third_party_zlib",
        "commit": "0a0c45d7e478826b59e67cc613be3e4b6957432c",
        "includes": [
            "crc32.c", "crc32.h", "deflate.c", "deflate.h", "gzclose.c", "gzguts.h",
            "gzlib.c", "gzread.c", "gzwrite.c", "infback.c", "inffast.c", "inffast.h",
            "inffixed.h", "inflate.c", "inflate.h", "inftrees.c", "inftrees.h",
            "trees.c", "trees.h", "uncompr.c", "zutil.c", "zutil.h", "zlib.h", "zconf.h",
            "contrib/minizip",
        ],
    },
}


def registry():
    result = DetectorRegistry()
    result.register(M2IpcInterfaceDetector())
    result.register(M2LifetimeDetector())
    result.register(M2SharedPtrRaceDetector())
    result.register(NullDereferenceDetector())
    return result


def git_head(repo: Path) -> str:
    done = subprocess.run(
        ["git", "-c", "remote.origin.promisor=false", "-C", str(repo), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True,
    )
    return done.stdout.strip()


def run_one(name: str) -> dict:
    target = TARGETS[name]
    repo = ROOT / name
    head = git_head(repo)
    if head != target["commit"]:
        raise RuntimeError(f"{name}: HEAD drift {head} != {target['commit']}")
    out = OUT_ROOT / name
    out.mkdir(parents=True, exist_ok=True)
    report = run_reviewed_detectors(
        repo_dir=repo,
        repository=target["repository"],
        commit=target["commit"],
        includes=tuple(target["includes"]),
        registry=registry(),
    )
    report["research_only_detectors"] = ["ohscanner.cpp.null_dereference"]
    report["catalog_registration"] = {
        "ohscanner.cpp.null_dereference": "not_registered_public_catalog",
        "reason": "A-CCR-04 owner approval explicitly set public_catalog_registration=false",
    }
    json_path = out / "report.json"
    md_path = out / "report.md"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [
        "# Third-party high-risk research scan",
        "",
        "> Research-only static candidates; not validated vulnerabilities.",
        "",
        f"- Repository: `{report['repository']}`",
        f"- Commit: `{report['commit']}`",
        f"- Status: `{report['status']}`",
        f"- Candidate observations: {report['diagnostic_count']}",
        f"- Source files: {report['scope']['selected_source_files']}",
        "",
        "## Detector results",
        "",
        "| Detector | Status | Diagnostics |",
        "|---|---|---:|",
    ]
    for run in report["detector_runs"]:
        lines.append(f"| `{run['tool']}` | {run['status']} | {run['diagnostic_count']} |")
    lines += ["", "## Limitations", ""]
    lines += ["- " + item for item in report["limitations"]]
    lines += [
        "- `ohscanner.cpp.null_dereference` is research-only and not registered in the public catalog.",
        "- Generic third-party C memory-safety weaknesses are outside the current approved IPC/shared_ptr/lifetime families.",
    ]
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {
        "name": name,
        "repository": report["repository"],
        "commit": report["commit"],
        "status": report["status"],
        "diagnostics": report["diagnostic_count"],
        "source_files": report["scope"]["selected_source_files"],
        "detector_counts": {run["tool"]: run["diagnostic_count"] for run in report["detector_runs"]},
        "output": str(out),
    }


if __name__ == "__main__":
    names = sys.argv[1:] or list(TARGETS)
    results = [run_one(name) for name in names]
    print(json.dumps(results, ensure_ascii=False, indent=2))
