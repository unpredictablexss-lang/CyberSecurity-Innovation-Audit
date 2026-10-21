#!/usr/bin/env python3
"""Replay CVE-2026-92392 against pinned Git objects without checking out source trees."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.detectors.known_cves import KnownDisclosedCveDetector

CURL_REPO_DEFAULT = "/tmp/d-curl-92392"
OH_CURL_REPO_DEFAULT = "/mnt/g/OpenHarmony-GitCode-Mirror/campaign-100-20261017/repos/third_party_curl"
CASES = (
    ("official_8_12_0_shape_variant", CURL_REPO_DEFAULT, "1d6e08ca3268a1f61bd4e56d6348fe304428ead7"),
    ("official_8_21_0_shape_variant", CURL_REPO_DEFAULT, "3f00a2f6fa97f7721b65606954aac979dcb6caac"),
    ("official_8_22_0_vulnerable", CURL_REPO_DEFAULT, "d0386aa3e805543ce464c993e1eb31b4d92c6356"),
    ("official_8_23_0_fixed", CURL_REPO_DEFAULT, "4c24dd7ba7244e0206d91a72fe414823add8a034"),
    ("openharmony_mirror_head", OH_CURL_REPO_DEFAULT, "1386bb128bb060b284309397b97adcaaec21c003"),
)
PATHS = ("lib/multi.c", "include/curl/curlver.h")


def git(repo: str, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", repo, *args])


def inspect_case(name: str, repo: str, revision: str) -> dict:
    raw = {path: git(repo, "show", f"{revision}:{path}") for path in sorted(PATHS)}
    units = tuple(
        SourceUnit(path=path, language="c", text=raw[path].decode("utf-8", errors="replace"),
                   sha256=hashlib.sha256(raw[path]).hexdigest(), parse_status="not_run")
        for path in sorted(PATHS)
    )
    request = ScanRequest(
        request_id=f"replay-{name}", repository=f"fixture/{name}", commit=revision,
        snapshot_sha256=snapshot_digest(units), target_id=f"current-component:fixture/{name}",
        profile_id="pinned-source-replay", provenance="fixture",
    )
    run = KnownDisclosedCveDetector().detect(ScanContext(request=request, units=units), units)
    findings = [finding for finding in run.findings if finding.symbol == "CVE-2026-92392"]
    version_match = re.search(r'^\s*#\s*define\s+LIBCURL_VERSION\s+"([^"]+)"', next(unit.text for unit in units if unit.path == "include/curl/curlver.h"), re.M)
    return {
        "name": name,
        "repository": "curl/curl" if name.startswith("official_") else "OpenHarmony third_party_curl mirror",
        "commit": git(repo, "rev-parse", revision).decode().strip(),
        "tree": git(repo, "rev-parse", f"{revision}^{{tree}}").decode().strip(),
        "source_paths": {
            path: {
                "blob": git(repo, "rev-parse", f"{revision}:{path}").decode().strip(),
                "sha256": hashlib.sha256(raw[path]).hexdigest(),
                "size": len(raw[path]),
            }
            for path in sorted(PATHS)
        },
        "source_declared_version": version_match.group(1) if version_match else None,
        "detector_status": run.status,
        "parse_status": "not_run",
        "findings": [
            {"line": finding.line, "rule_id": finding.rule_id, "cwe": finding.candidate_cwe,
             "source_sha256": finding.source_sha256, "message": finding.message}
            for finding in findings
        ],
        "candidate_count": len(findings),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--curl-repo", default=CURL_REPO_DEFAULT)
    parser.add_argument("--openharmony-curl-repo", default=OH_CURL_REPO_DEFAULT)
    parser.add_argument("--output", default=str(Path(__file__).with_name("D38_CVE_2026_92392_REPLAY.json")))
    args = parser.parse_args()
    cases = []
    for name, default_repo, revision in CASES:
        repo = args.openharmony_curl_repo if name == "openharmony_mirror_head" else args.curl_repo
        cases.append(inspect_case(name, repo, revision))
    result = {
        "schema": 1,
        "experiment": "D38 CVE-2026-92392 pinned source replay",
        "advisory": "https://curl.se/docs/CVE-2026-92392.html",
        "fix_commit": "https://github.com/curl/curl/commit/8b0744af5b1b631da5b938ca31c3f9895ad5a321",
        "detector": KnownDisclosedCveDetector.detector_id,
        "detector_version": KnownDisclosedCveDetector.version,
        "validated_vulnerability": 0,
        "product_status": "unknown",
        "limitations": [
            "This is a lexical source-signature replay over pinned Git objects; Tree-sitter parsing and full repository scanning were not run.",
            "The OpenHarmony G-drive mirror was read only through committed Git objects because its worktree is dirty; the committed HEAD identifies curl 8.8.0.",
            "The advisory's HTTP/2 upload reset preconditions, shipped product linkage, exploitability, and impact were not validated.",
            "A candidate signature and an upstream fix comparison do not confirm a product vulnerability.",
        ],
        "cases": cases,
    }
    Path(args.output).write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"output": args.output, "cases": [{"name": c["name"], "version": c["source_declared_version"], "candidates": c["candidate_count"], "status": c["detector_status"]} for c in cases]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
