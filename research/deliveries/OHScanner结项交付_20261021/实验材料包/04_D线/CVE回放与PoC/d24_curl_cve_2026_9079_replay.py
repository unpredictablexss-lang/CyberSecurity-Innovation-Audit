from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.ohscanner.detectors.known_cves import KnownDisclosedCveDetector
from src.ohscanner.execution import run_reviewed_detectors
from src.ohscanner.runner import DetectorRegistry

REPO = Path("/mnt/g/OpenHarmony-GitCode-Mirror/campaign-100-20261017/repos/third_party_curl")
COMMIT = "1386bb128bb060b284309397b97adcaaec21c003"
PATHS = ("include/curl/curlver.h", "lib/setopt.c")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "research/data_sensitive/D24_CURL_CVE_2026_9079_REPLAY.json")
    args = parser.parse_args()
    registry = DetectorRegistry()
    registry.register(KnownDisclosedCveDetector())
    first = run_reviewed_detectors(REPO, "OpenHarmony-GitCode-Mirror/third_party_curl", COMMIT, PATHS, registry)
    second = run_reviewed_detectors(REPO, "OpenHarmony-GitCode-Mirror/third_party_curl", COMMIT, PATHS, registry)
    run = first["detector_runs"][0]
    candidates = [finding for finding in run["diagnostics"] if finding["symbol"] == "CVE-2026-9079"]
    signature = lambda report: [
        (finding["file"], finding["line"], finding["rule_id"], finding["symbol"], finding["source_sha256"])
        for item in report["detector_runs"] for finding in item["diagnostics"]
    ]
    stable = (
        first["git_tree"] == second["git_tree"]
        and first["snapshot_sha256"] == second["snapshot_sha256"]
        and first["detector_coverage"] == second["detector_coverage"]
        and signature(first) == signature(second)
    )
    assert stable and not candidates
    sources = {}
    for path in PATHS:
        raw = subprocess.check_output(["git", "-C", str(REPO), "show", f"{COMMIT}:{path}"])
        sources[path] = {
            "blob": subprocess.check_output(["git", "-C", str(REPO), "rev-parse", f"{COMMIT}:{path}"], text=True).strip(),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
    result = {
        "schema": 1,
        "experiment": "D24 curl CVE-2026-9079 fixed-shape source replay",
        "detector": KnownDisclosedCveDetector.detector_id,
        "detector_version": KnownDisclosedCveDetector.version,
        "repository": "OpenHarmony-GitCode-Mirror/third_party_curl",
        "commit": first["commit"],
        "tree": first["git_tree"],
        "snapshot_sha256": first["snapshot_sha256"],
        "source_bindings": sources,
        "status": run["status"],
        "coverage": first["detector_coverage"]["detectors"][run["tool"]],
        "cve_2026_9079_candidates": [],
        "repeat_stable": stable,
        "validated_vulnerability": first["validated_vulnerability"],
        "limitations": [
            "The source has partial Tree-sitter coverage; no candidate is not a safe verdict for the whole source or repository.",
            "The selected files show curl 8.8.0 and unconditional proxy-credential clearing equivalent to upstream fix commit 88c7e16cceec816a2df45c89; this does not prove cherry-pick ancestry.",
            "The positive vulnerable shape is a regression fixture based on the upstream patch diff; no vulnerable product build was run.",
            "No OpenHarmony product build inclusion, caller sequence, credential exposure in a product, or impact is established.",
        ],
    }
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "detector_version": result["detector_version"], "commit": result["commit"], "status": result["status"], "coverage": result["coverage"]["status"], "source_bindings": sources, "candidates": len(candidates), "repeat_stable": stable, "validated_vulnerability": 0}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
