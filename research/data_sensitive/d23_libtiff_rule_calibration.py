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
from src.ohscanner.execution import run_reviewed_detectors
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.runner import DetectorRegistry

REPO = Path("/mnt/g/OpenHarmony-GitCode-Mirror/campaign-100-20261017/repos/third_party_libtiff")
COMMIT = "d4a0516c477dfbaf1153ae295893ab75aadd63d4"
SOURCE_PATH = "libtiff/tif_getimage.c"


def public_replay():
    registry = DetectorRegistry()
    registry.register(KnownDisclosedCveDetector())
    first = run_reviewed_detectors(REPO, "OpenHarmony-GitCode-Mirror/third_party_libtiff", COMMIT, (SOURCE_PATH,), registry)
    second = run_reviewed_detectors(REPO, "OpenHarmony-GitCode-Mirror/third_party_libtiff", COMMIT, (SOURCE_PATH,), registry)
    run = first["detector_runs"][0]
    findings = run["diagnostics"]
    stable = (
        first["git_tree"] == second["git_tree"]
        and first["snapshot_sha256"] == second["snapshot_sha256"]
        and first["detector_coverage"] == second["detector_coverage"]
        and [(f["file"], f["line"], f["rule_id"], f["symbol"], f["source_sha256"]) for f in findings]
        == [(f["file"], f["line"], f["rule_id"], f["symbol"], f["source_sha256"]) for f in second["detector_runs"][0]["diagnostics"]]
    )
    assert stable
    assert len(findings) == 1 and findings[0]["symbol"] == "CVE-2025-9900"
    assert findings[0]["line"] == 621
    return {
        "commit": first["commit"],
        "tree": first["git_tree"],
        "snapshot_sha256": first["snapshot_sha256"],
        "status": run["status"],
        "coverage": first["detector_coverage"]["detectors"][run["tool"]],
        "findings": [{key: finding[key] for key in ("file", "line", "rule_id", "symbol", "source_sha256", "message")} for finding in findings],
        "repeat_stable": stable,
        "validated_vulnerability": first["validated_vulnerability"],
    }


def fixed_shape_control():
    text = """int TIFFReadRGBAImageOriented(TIFF *tif, uint32_t rwidth, uint32_t rheight, uint32_t *raster, int orientation, int stop) {
    ok = TIFFRGBAImageGet(&img, raster, rwidth, rheight);
    return ok;
}
"""
    source = SourceUnit(SOURCE_PATH, "c", text, hashlib.sha256(text.encode()).hexdigest(), "complete")
    request = ScanRequest("d23-fixed-shape-control", "fixture/libtiff", "a" * 40, snapshot_digest((source,)), "current-component:fixture/libtiff", "fixture-no-build", "fixture")
    result = KnownDisclosedCveDetector().detect(ScanContext(request, (source,)), (source,))
    assert not any(finding.symbol == "CVE-2025-9900" for finding in result.findings)
    return {"kind": "synthetic_fixed_api_shape", "status": result.status, "cve_2025_9900_findings": 0}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "research/data_sensitive/D23_LIBTIFF_CVE_2025_9900_REPLAY.json")
    args = parser.parse_args()
    blob = subprocess.check_output(["git", "-C", str(REPO), "rev-parse", f"{COMMIT}:{SOURCE_PATH}"], text=True).strip()
    source = subprocess.check_output(["git", "-C", str(REPO), "show", f"{COMMIT}:{SOURCE_PATH}"])
    result = {
        "schema": 1,
        "experiment": "D23 libtiff CVE-2025-9900 rule calibration",
        "detector": KnownDisclosedCveDetector.detector_id,
        "detector_version": KnownDisclosedCveDetector.version,
        "pinned_source": {
            "repository": "OpenHarmony-GitCode-Mirror/third_party_libtiff",
            "commit": COMMIT,
            "tree": subprocess.check_output(["git", "-C", str(REPO), "rev-parse", f"{COMMIT}^{{tree}}"], text=True).strip(),
            "path": SOURCE_PATH,
            "blob": blob,
            "sha256": hashlib.sha256(source).hexdigest(),
        },
        "public_runner_replay": public_replay(),
        "fixed_shape_control": fixed_shape_control(),
        "limitations": [
            "The pinned source scan remains blocked with partial parser coverage; a local candidate is not a complete negative result.",
            "The synthetic fixed-shape control exercises the API call shape from the upstream patch, not an independently fetched fixed source tree.",
            "The upstream issue contains a component crash harness and the G-drive audit records a prior isolated ASan reproduction, but this experiment did not rerun the dynamic PoC.",
            "No OpenHarmony product entry, build inclusion, runtime impact, or affected release is established; validated_vulnerability remains zero.",
        ],
    }
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "detector_version": result["detector_version"], "candidate": result["public_runner_replay"]["findings"][0], "repeat_stable": result["public_runner_replay"]["repeat_stable"], "fixed_shape_control": result["fixed_shape_control"], "coverage_status": result["public_runner_replay"]["coverage"]["status"], "validated_vulnerability": 0}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
