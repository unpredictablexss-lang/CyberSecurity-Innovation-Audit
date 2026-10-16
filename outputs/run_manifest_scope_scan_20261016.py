#!/usr/bin/env python3
from __future__ import annotations
import json
import os
from pathlib import Path
import re
import subprocess
import sys

PROJECT = Path("/mnt/e/网安/CyberSecurity-Innovation-Audit")
MANIFEST_ROOT = PROJECT / "research/evidence/cpp/component_scans"
OUT_ROOT = PROJECT / "outputs/reports/community_scan_20261016"
DETECTORS = (
    "ohscanner.interface.ipc",
    "ohscanner.cpp.lifetime",
    "ohscanner.cpp.shared_ptr_race",
)

def source_repo_path(raw: str) -> str:
    if re.match(r"^[A-Za-z]:[\\/]", raw) and os.name != "nt":
        drive = raw[0].lower()
        rest = raw[2:].replace("\\", "/")
        return str(Path("/mnt") / drive / rest.lstrip("/"))
    return raw


def run_one(component: str) -> dict:
    manifest_path = MANIFEST_ROOT / f"{component}.manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    out = OUT_ROOT / f"{component}_production_scope"
    out.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable, "-m", "src.cli", "ohscan-run",
        "--repo-dir", source_repo_path(manifest["source_repo_path"]),
        "--repository", manifest["repository"],
        "--commit", manifest["commit"],
    ]
    for shard in manifest["shards"]:
        for path in shard["paths"]:
            command.extend(("--include", path))
    for detector in DETECTORS:
        command.extend(("--detector", detector))
    command.extend((
        "--json-out", str(out / "report.json"),
        "--md-out", str(out / "report.md"),
    ))
    (out / "command.json").write_text(
        json.dumps({"manifest": str(manifest_path), "command": command}, indent=2) + "\n",
        encoding="utf-8",
    )
    done = subprocess.run(command, cwd=PROJECT, text=True, capture_output=True)
    (out / "terminal.txt").write_text(done.stdout + done.stderr, encoding="utf-8")
    result = {
        "component": component,
        "returncode": done.returncode,
        "manifest": str(manifest_path),
        "manifest_sha256": __import__("hashlib").sha256(manifest_path.read_bytes()).hexdigest(),
        "selected_files": manifest["counts"]["selected_files"],
        "selected_bytes": manifest["counts"]["selected_bytes"],
        "output": str(out),
    }
    if done.returncode == 0:
        report = json.loads((out / "report.json").read_text(encoding="utf-8"))
        result.update({
            "repository": report["repository"],
            "commit": report["commit"],
            "status": report["status"],
            "diagnostics": report["diagnostic_count"],
            "detector_counts": {
                row["tool"]: row["diagnostic_count"] for row in report["detector_runs"]
            },
        })
    return result

if __name__ == "__main__":
    components = sys.argv[1:] or [
        "distributeddatamgr_kv_store",
        "window_window_manager",
        "communication_dsoftbus",
    ]
    results = [run_one(component) for component in components]
    print(json.dumps(results, ensure_ascii=False, indent=2))
    if any(item["returncode"] for item in results):
        raise SystemExit(1)
