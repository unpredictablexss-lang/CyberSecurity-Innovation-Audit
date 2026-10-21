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

REPOSITORY = "openharmony/filemanagement_storage_service"
SOURCE_PATH = "services/storage_daemon/volume/src/external_volume_info.cpp"
HELPER_PATH = "services/storage_daemon/utils/file_utils.cpp"
PAIRS = {
    "5.1": {
        "before": {
            "commit": "bf13f7daa06915e02788086f8450527eeb90f250",
            "tree": "3bc313e472d1bf54bea37623f86891666969c798",
            "blob": "292fc32c75b40d0d125a0cb8c33f0ef3e4d33663",
            "sha256": "c8784e1ba51410c5eeb1a5fbb4b5006d60fcff7fbd8b293e6e7ef046c54bf789",
        },
        "after": {
            "commit": "ef5145b591456f467531b5f6d38c124392b02e80",
            "tree": "6caf5f2df9babd5b34f0683cc66073b6a08850bd",
            "blob": "ba7f0d5f521675ac05fca8f912e2541af5a06743",
            "sha256": "5de1a7e2f29b701057d71317897722b0dc10fa2373649ac8649aa9bc4b86a89f",
        },
        "helper": {
            "blob": "24247006d6b83a93415b3faddc913fe8cf5db1d9",
            "sha256": "7760d5f7c50257475118cae57059de5c695011a346bca9ee63dac36d8c79bb75",
        },
    },
    "6.0": {
        "before": {
            "commit": "3f0a6a2b0dc3f81fe4562ace4681be50243aaf8f",
            "tree": "8d5556ae7f3641cb0b932022764e58242a3fb9fb",
            "blob": "a2e416bdc093bf9b8735a7917f4e877e25d4e7ae",
            "sha256": "c92f00fb756fdc6616d2462be0db29cf6b9504b6810b8e0e5a8b377b51368b03",
        },
        "after": {
            "commit": "7f9e44c24eb27bf2e458f9b7a03c6311983ec912",
            "tree": "788d533f633aaffe980f8699aede0fae67595bbf",
            "blob": "13d7619f7a0d1b0210002fa64e91749ff2793d79",
            "sha256": "217ec7692fab927dd2246cc47b923104129021bbc39bbb1e844269ef79421054",
        },
        "helper": {
            "blob": "7111ede2ed344cd3c0944fb2ac965e96d70e8f5b",
            "sha256": "41a8ade7eab4137172e2ca875eb5739bd407eacacd9fcd32a83a871396f5b7f9",
        },
    },
}


def git(repo: Path, *args: str) -> bytes:
    return subprocess.run(["git", "-C", str(repo), *args], check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def load_source(repo: Path, revision: dict, label: str) -> tuple[dict, bytes]:
    commit = revision["commit"]
    actual_tree = git(repo, "rev-parse", f"{commit}^{{tree}}").decode().strip()
    raw = git(repo, "show", f"{commit}:{SOURCE_PATH}")
    actual_blob = git(repo, "rev-parse", f"{commit}:{SOURCE_PATH}").decode().strip()
    actual_sha256 = hashlib.sha256(raw).hexdigest()
    if (actual_tree, actual_blob, actual_sha256) != (
            revision["tree"], revision["blob"], revision["sha256"]):
        raise ValueError(f"{label} source identity mismatch")
    return ({"commit": commit, "tree": actual_tree, "path": SOURCE_PATH,
             "blob": actual_blob, "sha256": actual_sha256, "size": len(raw)}, raw)


def scan(raw: bytes, commit: str) -> dict:
    text = raw.decode("utf-8")
    unit = SourceUnit(path=SOURCE_PATH, language="cpp", text=text,
                      sha256=hashlib.sha256(raw).hexdigest(), parse_status="not_run")
    request = ScanRequest(
        request_id=f"d35-storage-{commit[:12]}", repository=REPOSITORY, commit=commit,
        snapshot_sha256=snapshot_digest((unit,)), target_id="current-component:" + REPOSITORY,
        profile_id="pinned-upstream-single-file", provenance="fixture",
    )
    run = KnownDisclosedCveDetector().detect(ScanContext(request=request, units=(unit,)), (unit,))
    findings = [f for f in run.findings if f.symbol == "CVE-2026-25850"]
    return {
        "detector_version": KnownDisclosedCveDetector.version,
        "status": run.status,
        "parse_status": "not_run",
        "findings": [{"file": f.file, "line": f.line, "rule_id": f.rule_id,
                      "symbol": f.symbol, "cwe": f.candidate_cwe,
                      "impact": f.consequence_impact, "source_sha256": f.source_sha256}
                     for f in findings],
    }


def load_helper(repo: Path, commit: str, expected: dict) -> dict:
    raw = git(repo, "show", f"{commit}:{HELPER_PATH}")
    blob = git(repo, "rev-parse", f"{commit}:{HELPER_PATH}").decode().strip()
    sha256 = hashlib.sha256(raw).hexdigest()
    text = raw.decode("utf-8")
    if (blob, sha256) != (expected["blob"], expected["sha256"]):
        raise ValueError(f"helper source identity mismatch at {commit}")
    if "TravelChmod(subpath, mode)" not in text or "ChMod(subpath, mode)" not in text:
        raise ValueError(f"recursive TravelChmod implementation not found at {commit}")
    return {"commit": commit, "path": HELPER_PATH, "blob": blob, "sha256": sha256,
            "recursive_self_call": True}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True,
                        help="local GitCode filemanagement_storage_service clone with pinned objects")
    parser.add_argument("--output", type=Path,
                        default=ROOT / "research/data_sensitive/D35_FILEMANAGEMENT_CVE_2026_25850_REPLAY.json")
    args = parser.parse_args()
    if not (args.repo / ".git").exists():
        raise SystemExit("--repo must be an existing Git repository; this script never fetches")
    result = {
        "schema": 1,
        "experiment": "D35 CVE-2026-25850 exact source candidate and upstream-fix replay",
        "repository": REPOSITORY,
        "detector": KnownDisclosedCveDetector.detector_id,
        "validated_vulnerability": 0,
        "product_status": "unknown",
        "limitations": [
            "The rule replay is a fixed-source detector check, not a runtime permission PoC.",
            "The two merge-request source pairs bind the vulnerable and permission-fix shapes; they do not prove a particular product image contains either revision.",
            "Tree-sitter parsing was not run in this direct one-file replay; runs remain blocked and findings remain candidates.",
        ],
        "pairs": {},
    }
    for branch, pair in PAIRS.items():
        before_meta, before_raw = load_source(args.repo, pair["before"], f"{branch}:before")
        after_meta, after_raw = load_source(args.repo, pair["after"], f"{branch}:after")
        before = scan(before_raw, pair["before"]["commit"])
        after = scan(after_raw, pair["after"]["commit"])
        helper = load_helper(args.repo, pair["before"]["commit"], pair["helper"])
        fixed_helper = load_helper(args.repo, pair["after"]["commit"], pair["helper"])
        if helper["blob"] != fixed_helper["blob"]:
            raise AssertionError(f"{branch} helper changed across the mount fix")
        if len(before["findings"]) != 2 or after["findings"]:
            raise AssertionError(f"{branch} expected two old-shape candidates and zero fixed-shape candidates")
        expected_sha = before_meta["sha256"]
        if {finding["source_sha256"] for finding in before["findings"]} != {expected_sha}:
            raise AssertionError(f"{branch} finding source binding mismatch")
        result["pairs"][branch] = {
            "before_source": before_meta, "before_scan": before,
            "after_source": after_meta, "after_scan": after,
            "helper_source": helper,
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "detector_version": KnownDisclosedCveDetector.version,
                      "results": {name: [len(row["before_scan"]["findings"]),
                                         len(row["after_scan"]["findings"])]
                                  for name, row in result["pairs"].items()},
                      "validated_vulnerability": 0}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
