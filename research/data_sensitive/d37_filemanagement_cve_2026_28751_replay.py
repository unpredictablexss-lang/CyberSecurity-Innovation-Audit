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
SOURCE_PATH = "services/storage_manager/volume/src/volume_manager_service.cpp"
REVISIONS = {
    "pre_fix": {
        "commit": "d55dc1f9195bf0301680a788d5b9487e67332382",
        "tree": "1f8765ac4fe099aaa8639118106278f5e535e3c8",
        "blob": "87b828d508be13e10bc9c4329e50ddb94e5a8480",
        "sha256": "1496b686567f618b3f675df1a8b6376feb9552de23b4ebb176ccd2edf47e6bef",
    },
    "linked_fix": {
        "commit": "aa3abd7e24050ef284064d9f800a3bc833d90538",
        "tree": "fd5381aee6fb2ff39e8b0c6db3b95dd86409266c",
        "blob": "7748401618bef99f2f0466f32918f3471ddaf1d3",
        "sha256": "08a0274382c4ace3ad8150b238d527da588ed08bcc04f990aaf0d2849f338854",
    },
    "release_6_0_head": {
        "commit": "b57b96459c324d5f0e0586cb70e5f7e41af76194",
        "tree": "9b397e7e570227c4fff8c84414e31120587ae33d",
        "blob": "99904767b05dce439737d407172f06788be2e6ee",
        "sha256": "0f02c9c167e71c232dea466d17f03ee8d688dbfc05121e6411ec1e7e0ce72f35",
    },
    "release_5_1_head": {
        "commit": "3b57e9d315910f390b52545125f5fc3334a35fe0",
        "tree": "5db0623b398593556fc222c86cf44073f9f39974",
        "blob": "1fed60231b71b906e3330215b30514030676faf4",
        "sha256": "5f1f2b0b2b89499953ad0037dfe580f379b5dc1bfc0d0d6cbede824c5d2c53f6",
    },
}


def git(repo: Path, *args: str) -> bytes:
    return subprocess.run(["git", "-C", str(repo), *args], check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def scan(repo: Path, label: str, revision: dict) -> dict:
    commit = revision["commit"]
    tree = git(repo, "rev-parse", f"{commit}^{{tree}}").decode().strip()
    blob = git(repo, "rev-parse", f"{commit}:{SOURCE_PATH}").decode().strip()
    raw = git(repo, "show", f"{commit}:{SOURCE_PATH}")
    sha256 = hashlib.sha256(raw).hexdigest()
    if (tree, blob, sha256) != (revision["tree"], revision["blob"], revision["sha256"]):
        raise ValueError(f"{label} Git identity mismatch")
    text = raw.decode("utf-8")
    unit = SourceUnit(path=SOURCE_PATH, language="cpp", text=text, sha256=sha256,
                      parse_status="not_run")
    request = ScanRequest(
        request_id=f"d37-cve-2026-28751-{commit[:12]}", repository=REPOSITORY,
        commit=commit, snapshot_sha256=snapshot_digest((unit,)),
        target_id="current-component:" + REPOSITORY,
        profile_id="pinned-upstream-single-file", provenance="fixture",
    )
    run = KnownDisclosedCveDetector().detect(ScanContext(request=request, units=(unit,)), (unit,))
    findings = [f for f in run.findings if f.symbol == "CVE-2026-28751"]
    return {
        "source": {"commit": commit, "tree": tree, "path": SOURCE_PATH,
                   "blob": blob, "sha256": sha256, "size": len(raw)},
        "signature_present": "NotifyMtpMounted" in text and "getxattr" in text,
        "status": run.status,
        "parse_status": "not_run",
        "findings": [{"line": f.line, "rule_id": f.rule_id, "cwe": f.candidate_cwe,
                      "source_sha256": f.source_sha256, "message": f.message}
                     for f in findings],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True,
                        help="existing local GitCode clone with the pinned objects; no fetch is performed")
    parser.add_argument("--output", type=Path,
                        default=ROOT / "research/data_sensitive/D37_CVE_2026_28751_REPLAY.json")
    args = parser.parse_args()
    if not (args.repo / ".git").exists():
        raise SystemExit("--repo must be a local Git repository")
    results = {name: scan(args.repo, name, revision)
               for name, revision in REVISIONS.items()}
    expected = {"pre_fix": 1, "linked_fix": 0, "release_6_0_head": 0, "release_5_1_head": 0}
    for name, count in expected.items():
        if len(results[name]["findings"]) != count:
            raise AssertionError(f"{name}: expected {count} finding(s)")
    if not results["pre_fix"]["signature_present"]:
        raise AssertionError("pre-fix MTP signature is not present")
    if results["release_5_1_head"]["signature_present"]:
        # This only records that this precise source signature is absent on 5.1;
        # it is not a clean/security verdict for the branch.
        pass
    result = {
        "schema": 1,
        "experiment": "D37 CVE-2026-28751 full-length MTP xattr source replay",
        "repository": REPOSITORY,
        "detector": KnownDisclosedCveDetector.detector_id,
        "detector_version": KnownDisclosedCveDetector.version,
        "validated_vulnerability": 0,
        "product_status": "unknown",
        "limitations": [
            "Pinned-source static replay only; Tree-sitter was not run and coverage remains blocked.",
            "The 5.1 source has no NotifyMtpMounted/getxattr signature in this file; zero findings there is not a security verdict.",
            "A source-shaped ASan harness demonstrates the full-length unterminated-string read, not a service build or product exploit.",
            "No product image, attacker-controlled MTP input path, or shipped build was verified.",
        ],
        "revisions": results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": str(args.output),
        "version": result["detector_version"],
        "findings": {name: len(item["findings"]) for name, item in results.items()},
        "signature_present": {name: item["signature_present"] for name, item in results.items()},
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
