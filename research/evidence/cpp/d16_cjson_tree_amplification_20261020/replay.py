#!/usr/bin/env python3
"""Replay the source-bound D16 cJSON tree-amplification candidate.

The third-party source stays outside this repository. Pass its checkout root
with --source-root; the script verifies the pinned commit, tree, blobs and byte
hashes before invoking the first-party detector.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPOSITORY_ROOT))

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.cpp.resource_lifetime_detector import CppResourceLifetimeDetector
from src.ohscanner.fixture import snapshot_digest


COMMIT = "105eaddbf0d0110b07d16bdefc81ffc796e1444a"
TREE = "3c07134d5a05aa546b15739e32503a2ca192d258"
SOURCES = {
    "cJSON.c": {
        "blob": "152b2caa479c9f448001652913c980a6dafb82e0",
        "sha256": "427c72055ae68467b451599f36da074351a5ca53f6e103cd30064e32cf0fffbb",
        "bytes": 80529,
        "parse_status": "partial",
    },
    "cJSON_Utils.c": {
        "blob": "8fa24f8e9bf452cf1ba49d1325c85423ce742c74",
        "sha256": "bf3092696763a9a446c39365d7c35f23e5acfdca1bd1da33ef66c1161f9243e9",
        "bytes": 40736,
        "parse_status": "complete",
    },
}


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", required=True, type=Path,
                        help="root of the exact third_party_cjson source checkout")
    args = parser.parse_args()
    root = args.source_root.resolve()
    observed_commit = git(root, "rev-parse", "HEAD^{commit}")
    observed_tree = git(root, "rev-parse", "HEAD^{tree}")
    if (observed_commit, observed_tree) != (COMMIT, TREE):
        raise SystemExit(f"source identity mismatch: {observed_commit} {observed_tree}")

    units = []
    identity = []
    for name, expected in SOURCES.items():
        relative = f"third_party/cjson/{name}"
        data = (root / relative).read_bytes()
        blob = git(root, "rev-parse", f"HEAD:{relative}")
        digest = hashlib.sha256(data).hexdigest()
        if (len(data), digest, blob) != (expected["bytes"], expected["sha256"], expected["blob"]):
            raise SystemExit(f"source byte/blob mismatch: {relative}")
        text = data.decode("utf-8")
        units.append(SourceUnit(relative, "c", text, digest, expected["parse_status"]))
        identity.append({"path": relative, "bytes": len(data), "blob": blob,
                         "sha256": digest, "parse_status": expected["parse_status"]})

    units = tuple(sorted(units, key=lambda unit: unit.path))
    repository = "openharmony/third_party_cjson"
    request = ScanRequest(
        request_id="D16-cJSON-CVE-2026-67215",
        repository=repository,
        commit=COMMIT,
        snapshot_sha256=snapshot_digest(units),
        target_id="current-component:" + repository,
        profile_id="light-ast",
        provenance="git_object",
    )
    run = CppResourceLifetimeDetector().detect(ScanContext(request, units), units)
    findings = [{"rule_id": item.rule_id, "file": item.file, "line": item.line,
                 "symbol": item.symbol, "source_sha256": item.source_sha256}
                for item in run.findings]
    result = {
        "schema_version": 1,
        "experiment_kind": "first_party_detector_execution",
        "detector": run.detector_id,
        "detector_version": run.version,
        "source_commit": COMMIT,
        "source_tree": TREE,
        "snapshot_sha256": request.snapshot_sha256,
        "status": run.status,
        "analyzed_files": list(run.analyzed_files),
        "sources": identity,
        "findings": findings,
        "limitations": list(run.limitations),
        "fixed_source": "no trusted root-matched fixed source bound",
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    expected_rule = "ohcpp-resource-exhaustion-tree-amplification-candidate-004"
    matches = [item for item in findings if item["rule_id"] == expected_rule
               and item["symbol"] == "apply_patch" and item["line"] == 861]
    if len(matches) != 1 or run.status != "blocked":
        raise SystemExit("expected source candidate or blocked partial coverage missing")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
