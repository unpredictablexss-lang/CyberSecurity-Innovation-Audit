from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "research" / "evidence" / "cpp"
EXPECTED = {
    "vulnerable": {
        "commit": "01346829096c61b372692f6dc43ffa778c6caccd",
        "tree": "6ae23d9333713707a02588b44ed238a50e8b3bde",
        "blob": "600437576581be08f9026881c39178857a1c5939",
        "sha256": "1f3388f52881524fda0bc11c453aca75adda7d7e77d65393ec558d396dc3483d",
        "snapshot": "c0ca047682dce16d7aec8a1607b06f7a0420602a6a0ae13b8195f6629a1ac730",
        "count": 1,
        "line": 1118,
    },
    "fixed": {
        "commit": "d7546809d5bd548b69ec49fca26565c8f6f0d344",
        "tree": "52a8416729366487cdd3b6012071f5f8370e769f",
        "blob": "3522679a16e2fa560c581413bf946d38e332bea4",
        "sha256": "ea7f9adccf81b578d97e8b6e115535e043b7f8c589177a2597963a4f12462b81",
        "snapshot": "cbc4bf484c7dacefd8869f7917b00983569e8d012470e88f278fc6104744c2f6",
        "count": 0,
    },
}
DETECTOR = "ohscanner.cpp.resource_lifetime"
RULE = "ohcpp-resource-lifetime-recursive-cleanup-candidate-003"


def git(git_dir: Path, *args: str) -> str:
    return subprocess.check_output(["git", f"--git-dir={git_dir}", *args], text=True).strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-git-dir", type=Path, required=True)
    args = parser.parse_args()
    audit = json.loads((EVIDENCE / "t32_curl_92391_independent_audit_20261023.json").read_text(encoding="utf-8"))
    assert audit["acceptance_head"] == "385e0266301793a45d9df84f7a18a3f1a3b07efc"
    assert audit["detector_version"] == "0.4.2"
    for variant in audit["variants"]:
        label = variant["label"]
        expected = EXPECTED[label]
        commit = expected["commit"]
        assert git(args.source_git_dir, "rev-parse", commit) == commit
        assert git(args.source_git_dir, "rev-parse", f"{commit}^{{tree}}") == expected["tree"]
        blob = git(args.source_git_dir, "rev-parse", f"{commit}:lib/mime.c")
        assert blob == expected["blob"]
        source = subprocess.check_output(["git", f"--git-dir={args.source_git_dir}", "show", f"{commit}:lib/mime.c"])
        assert hashlib.sha256(source).hexdigest() == expected["sha256"]
        report_path = EVIDENCE / variant["cli_report"]
        report = json.loads(report_path.read_text(encoding="utf-8"))
        run = report["detector_runs"][0]
        assert report["commit"] == commit
        assert report["git_tree"] == expected["tree"]
        assert report["snapshot_sha256"] == expected["snapshot"]
        assert report["scope"]["declared_scope"] == ["lib/mime.c"]
        assert report["audit_plan"]["source"]["files"] == [{
            "path": "lib/mime.c", "language": "c", "sha256": expected["sha256"],
            "parse_status": "complete", "blob_oid": expected["blob"], "archive_binding": None,
        }]
        assert run["tool"] == DETECTOR and run["tool_version"] == "0.4.2"
        assert run["status"] == "completed" and run["parsing"][0]["status"] == "complete"
        coverage = report["detector_coverage"]["detectors"][DETECTOR]
        assert coverage["status"] == "complete"
        findings = [finding for finding in run["diagnostics"] if finding["rule_id"] == RULE]
        assert len(findings) == expected["count"]
        if label == "vulnerable":
            assert findings[0]["file"] == "lib/mime.c" and findings[0]["line"] == expected["line"]
            assert findings[0]["symbol"] == "curl_mime_free"
            assert findings[0]["finding_identity"]["stable"]["status"] == "unknown"
    assert audit["static_differential"] == "PASS"
    assert audit["product_or_cve_disposition"] == "PARTIAL/BLOCK"
    print("PASS: exact curl commit/tree/blob/SHA, current-version CLI, complete coverage, 1/0 same-rule differential")
    print("PASS: candidate identity/product limitations remain PARTIAL/BLOCK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
