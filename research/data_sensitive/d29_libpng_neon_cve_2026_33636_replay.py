#!/usr/bin/env python3
"""Offline, source-bound replay for the libpng ARM NEON palette rule."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.known_cves import KnownDisclosedCveDetector
from src.ohscanner.fixture import snapshot_digest

FIXTURES = ROOT / "tests/fixtures/data_sensitive/cve_2026_33636"
SAMPLES = (
    {
        "name": "libpng-1.6.55-vulnerable",
        "path": FIXTURES / "libpng-1.6.55-palette_neon_intrinsics.c",
        "commit": "c3e304954a9cfd154bc0dfbfea2b01cd61d6546d",
        "git_blob_sha1": "3068e9b6e62be16bee2a8f1ff8271a02f32be97f",
        "sha256": "d58734a03a91df0f2c11e3558354281d7613888d85c83887586560a270bffa41",
        "expected_findings": 2,
    },
    {
        "name": "libpng-1.6.56-fixed",
        "path": FIXTURES / "libpng-1.6.56-palette_neon_intrinsics.c",
        "commit": "d5515b5b8be3901aac04e5bd8bd5c89f287bcd33",
        "git_blob_sha1": "0967ea1aebd718907fda1e767957deeddbe676b3",
        "sha256": "a844760f611829df29ca583f1b08832cac1440c74a2a22b35bc35a464ddf6b5e",
        "expected_findings": 0,
    },
)
ROUNDS = 3


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def scan(sample: dict):
    content = sample["path"].read_bytes()
    actual_sha = sha256(content)
    actual_blob = git_blob_sha1(content)
    if actual_sha != sample["sha256"] or actual_blob != sample["git_blob_sha1"]:
        raise SystemExit(f"source integrity mismatch: {sample['path']}")
    unit = SourceUnit(
        path="arm/palette_neon_intrinsics.c", language="c", text=content.decode("utf-8"),
        sha256=actual_sha, parse_status="not_run",
    )
    request = ScanRequest(
        request_id=f"d29:{sample['name']}", repository="pnggroup/libpng",
        commit=sample["commit"], snapshot_sha256=snapshot_digest((unit,)),
        target_id="current-component:pnggroup/libpng", profile_id="pinned-upstream-source",
        provenance="fixture",
    )
    run = KnownDisclosedCveDetector().detect(ScanContext(request=request, units=(unit,)), (unit,))
    findings = [finding for finding in run.findings if finding.symbol == "CVE-2026-33636"]
    identities = sorted(
        f"{finding.file}:{finding.line}:{finding.rule_id}:{finding.source_sha256}"
        for finding in findings
    )
    return {
        "source": sample["name"], "commit": sample["commit"],
        "git_blob_sha1": actual_blob, "source_sha256": actual_sha,
        "parser_status": "not_run", "detector_status": run.status,
        "candidate_count": len(findings), "candidate_identities": identities,
        "coverage_limitations": list(run.limitations),
        "validated_vulnerability": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name("D29_LIBPNG_NEON_CVE_2026_33636_REPLAY.json"))
    args = parser.parse_args()
    rounds = []
    for index in range(1, ROUNDS + 1):
        result = {sample["name"]: scan(sample) for sample in SAMPLES}
        for sample in SAMPLES:
            actual = result[sample["name"]]["candidate_count"]
            if actual != sample["expected_findings"]:
                raise SystemExit(f"unexpected {sample['name']} candidate count: {actual}")
        rounds.append({"round": index, "samples": result})
    if any(round_["samples"] != rounds[0]["samples"] for round_ in rounds[1:]):
        raise SystemExit("candidate identities or coverage changed between rounds")
    document = {
        "schema": 1, "experiment": "D29 libpng ARM NEON palette CVE-2026-33636 source replay",
        "detector_id": "ohscanner.known_disclosed_cves", "detector_version": KnownDisclosedCveDetector.version,
        "rounds": rounds,
        "interpretation": "Pinned component-source regression only. The vulnerable source is a candidate, not an OpenHarmony product vulnerability confirmation. Both runs skip parsing and report blocked coverage.",
        "validated_vulnerability": 0,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"rounds": ROUNDS, "candidates_per_round": {
        name: result["candidate_count"] for name, result in rounds[0]["samples"].items()
    }, "output": str(args.output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
