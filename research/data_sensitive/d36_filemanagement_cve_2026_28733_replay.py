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
SOURCE_PATH = "services/storage_daemon/ipc/src/storage_daemon_stub.cpp"
REVISIONS = {
    "pre_mutex_patch": {
        "commit": "4bd078b3d4034af725f42a69bd67b4806fc6e717",
        "tree": "4b0cbb0130e7faa9f6f051f3e1dec6e82056ebd3",
        "blob": "5a37ad52342b142febdad606117aa44b8f10571c",
        "sha256": "e06307d35da9b63d4156b6dceb53535aef5727cfb2a57be81844570e8f81b07a",
    },
    "linked_mutex_patch": {
        "commit": "677d6602226d64631fb136fbeabdc39ab5a7eaca",
        "tree": "cbee8ce589a1e71552f60c6afaef4852cdc4dda1",
        "blob": "0867f44d8975e110467c57da3a2f4d4d9cd4fe1c",
        "sha256": "5824805944cd88868ab9a47d7a548a7ffe909b1a17e23d09c73100feb8a4403e",
    },
    "release_5_1_current": {
        "commit": "3b57e9d315910f390b52545125f5fc3334a35fe0",
        "tree": "5db0623b398593556fc222c86cf44073f9f39974",
        "blob": "0867f44d8975e110467c57da3a2f4d4d9cd4fe1c",
        "sha256": "5824805944cd88868ab9a47d7a548a7ffe909b1a17e23d09c73100feb8a4403e",
    },
}


def git(repo: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ).stdout


def source_at(repo: Path, label: str, revision: dict) -> tuple[dict, bytes]:
    commit = revision["commit"]
    tree = git(repo, "rev-parse", f"{commit}^{{tree}}").decode().strip()
    blob = git(repo, "rev-parse", f"{commit}:{SOURCE_PATH}").decode().strip()
    raw = git(repo, "show", f"{commit}:{SOURCE_PATH}")
    sha256 = hashlib.sha256(raw).hexdigest()
    actual = (tree, blob, sha256)
    expected = (revision["tree"], revision["blob"], revision["sha256"])
    if actual != expected:
        raise ValueError(f"{label} source identity mismatch: {actual!r}")
    return ({
        "commit": commit, "tree": tree, "path": SOURCE_PATH,
        "blob": blob, "sha256": sha256, "size": len(raw),
    }, raw)


def scan(raw: bytes, commit: str) -> dict:
    text = raw.decode("utf-8")
    unit = SourceUnit(
        path=SOURCE_PATH, language="cpp", text=text,
        sha256=hashlib.sha256(raw).hexdigest(), parse_status="not_run",
    )
    request = ScanRequest(
        request_id=f"d36-cve-2026-28733-{commit[:12]}",
        repository=REPOSITORY, commit=commit,
        snapshot_sha256=snapshot_digest((unit,)),
        target_id="current-component:" + REPOSITORY,
        profile_id="pinned-upstream-single-file", provenance="fixture",
    )
    run = KnownDisclosedCveDetector().detect(
        ScanContext(request=request, units=(unit,)), (unit,),
    )
    findings = [finding for finding in run.findings if finding.symbol == "CVE-2026-28733"]
    return {
        "status": run.status,
        "parse_status": "not_run",
        "validated_vulnerability": 0,
        "findings": [{
            "file": finding.file, "line": finding.line, "rule_id": finding.rule_id,
            "symbol": finding.symbol, "cwe": finding.candidate_cwe,
            "source_sha256": finding.source_sha256, "message": finding.message,
        } for finding in findings],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True,
                        help="local GitCode filemanagement_storage_service clone containing pinned commits")
    parser.add_argument("--output", type=Path,
                        default=ROOT / "research/data_sensitive/D36_CVE_2026_28733_REPLAY.json")
    args = parser.parse_args()
    if not (args.repo / ".git").exists():
        raise SystemExit("--repo must be an existing Git repository; this replay never fetches")
    results = {}
    for label, revision in REVISIONS.items():
        meta, raw = source_at(args.repo, label, revision)
        results[label] = {"source": meta, "scan": scan(raw, revision["commit"])}
        if len(results[label]["scan"]["findings"]) != 1:
            raise AssertionError(f"{label}: expected one iterator-lifetime candidate")
        if results[label]["scan"]["findings"][0]["source_sha256"] != meta["sha256"]:
            raise AssertionError(f"{label}: finding source binding mismatch")
    result = {
        "schema": 1,
        "experiment": "D36 CVE-2026-28733 iterator lifetime source replay",
        "repository": REPOSITORY,
        "detector": KnownDisclosedCveDetector.detector_id,
        "detector_version": KnownDisclosedCveDetector.version,
        "root_cause": "locked getter returns shared std::map iterator; another locked method clears that map; handlers use the escaped iterator after the getter lock is gone",
        "validated_vulnerability": 0,
        "product_status": "unknown",
        "limitations": [
            "Pinned-source static replay only; Tree-sitter was not run, so coverage status remains blocked.",
            "The companion ASan harness is a source-shaped C++ model, not a build of the OpenHarmony service or a product exploit.",
            "The official mutex patch adds locks around map operations but leaves iterator lifetime outside those lock scopes.",
            "No specific OpenHarmony product image, build inclusion, or reachable local attacker path was verified.",
        ],
        "revisions": results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": str(args.output),
        "version": result["detector_version"],
        "findings": {key: len(value["scan"]["findings"]) for key, value in results.items()},
        "validated_vulnerability": 0,
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
