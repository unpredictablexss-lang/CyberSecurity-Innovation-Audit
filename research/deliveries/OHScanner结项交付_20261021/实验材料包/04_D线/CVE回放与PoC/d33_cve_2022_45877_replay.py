#!/usr/bin/env python3
"""Replay CVE-2022-45877 against pinned upstream source commits.

Requires a local clone of openharmony/distributedhardware_device_manager with
both the fix commit and its parent available. The script reads git objects only.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.known_cves import KnownDisclosedCveDetector
from src.ohscanner.fixture import snapshot_digest

FIX = "8bea775dc169bca2d9a1ce57ada2d86cbd179163"
OLD = "97c3d5c7b07a0ab599afcc1464143b255e7dbb68"
RELATIVE = "services/devicemanagerservice/src/authentication/dm_auth_manager.cpp"

def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()

def source(repo: Path, commit: str) -> tuple[str, str]:
    text = subprocess.check_output(
        ["git", "-C", str(repo), "show", f"{commit}:{RELATIVE}"]
    ).decode("utf-8")
    return text, hashlib.sha256(text.encode()).hexdigest()

def scan(text: str, sha: str, commit: str) -> dict:
    unit = SourceUnit(path=RELATIVE, language="cpp", text=text, sha256=sha, parse_status="partial")
    request = ScanRequest(
        request_id=f"d-cve-2022-45877:{commit}", repository="openharmony/distributedhardware_device_manager",
        commit=commit, snapshot_sha256=snapshot_digest((unit,)),
        target_id="current-component:openharmony/distributedhardware_device_manager", profile_id="light-ast",
        provenance="git_object",
    )
    run = KnownDisclosedCveDetector().detect(ScanContext(request=request, units=(unit,)), (unit,))
    findings = [f for f in run.findings if f.symbol == "CVE-2022-45877"]
    return {
        "commit": commit, "source_sha256": sha, "status": run.status,
        "parse_status": "partial", "candidate_count": len(findings),
        "findings": [{
            "file": f.file, "line": f.line, "rule_id": f.rule_id, "symbol": f.symbol,
            "candidate_cwe": f.candidate_cwe, "message": f.message,
        } for f in findings],
        "limitations": list(run.limitations),
    }

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True, type=Path, help="local upstream repository clone")
    parser.add_argument("--output", type=Path, help="write JSON result here")
    args = parser.parse_args()
    repo = args.repo.resolve()
    parent = git(repo, "rev-parse", f"{FIX}^")
    if parent != OLD:
        raise SystemExit(f"unexpected parent for fix: {parent}")
    rows = []
    for commit in (OLD, FIX):
        text, sha = source(repo, commit)
        rows.append(scan(text, sha, commit))
    if rows[0]["candidate_count"] != 1 or rows[1]["candidate_count"] != 0:
        raise SystemExit("expected old-source candidate and fixed-source no-match")
    result = {
        "cve": "CVE-2022-45877", "detector_version": KnownDisclosedCveDetector.version,
        "upstream_repository": "https://github.com/openharmony/distributedhardware_device_manager",
        "fix_commit": FIX, "old_commit": OLD, "source_path": RELATIVE,
        "evidence_boundary": "component source regression only; no OpenHarmony product build or dynamic device test",
        "runs": rows,
    }
    rendered = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
