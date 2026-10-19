"""Verify the source-bound facts in the T4 historical rescan package."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def read(name: str) -> dict:
    return json.loads((ROOT / f"{name}.json").read_text(encoding="utf-8"))


def check_case(name: str, commit: str, detector: str, version: str, coverage: str,
               expected: set[tuple[str, int, str]], source_hashes: set[str]) -> None:
    report = read(name)
    assert report["commit"] == commit, (name, report.get("commit"))
    assert report["validated_vulnerability"] == 0
    runs = [run for run in report["detector_runs"] if run["tool"] == detector]
    assert len(runs) == 1
    run = runs[0]
    assert run["tool_version"] == version
    assert run["status"] == ("blocked" if coverage == "partial" else "completed")
    observed = {
        (finding.get("symbol", ""), finding["line"], finding["rule_id"])
        for finding in run["diagnostics"]
    }
    assert observed == expected, (name, observed)
    detector_coverage = report["detector_coverage"]["detectors"][detector]
    assert detector_coverage["status"] == coverage
    assert set(detector_coverage["source_sha256"].values()) == source_hashes


def main() -> None:
    curl_detector = "ohscanner.cpp.resource_lifetime"
    curl_rule = "ohcpp-resource-lifetime-recursive-cleanup-candidate-003"
    check_case(
        "curl_vulnerable", "01346829096c61b372692f6dc43ffa778c6caccd",
        curl_detector, "0.4.2", "complete",
        {("curl_mime_free", 1118, curl_rule)},
        {"1f3388f52881524fda0bc11c453aca75adda7d7e77d65393ec558d396dc3483d"},
    )
    check_case(
        "curl_fixed", "d7546809d5bd548b69ec49fca26565c8f6f0d344",
        curl_detector, "0.4.2", "complete", set(),
        {"ea7f9adccf81b578d97e8b6e115535e043b7f8c589177a2597963a4f12462b81"},
    )
    paste_detector = "ohscanner.known_disclosed_cves"
    check_case(
        "pasteboard_legacy", "dd22c7cb5e5f207a6c38c50f45b7369ee8575840",
        paste_detector, "0.16.0", "complete",
        {
            ("CVE-2025-25212", 222, "ohknowncve-pasteboard-cve-2025-25212"),
            ("CVE-2025-27247", 41, "ohknowncve-pasteboard-cve-2025-27247"),
        },
        {
            "73847a64595c9c3f4c3e9ff2ea6bdea17db9cf45f02faf1436fe1b6753a73a52",
            "d2e166bc3e04edd2b53060429b7be137c79d11be393436f4e7a8b1e54a1f7868",
        },
    )
    later = read("pasteboard_later_snapshot")
    assert later["commit"] == "e73747b227104e6743e957ce31040edf58507221"
    assert later["validated_vulnerability"] == 0
    run = later["detector_runs"][0]
    assert run["tool"] == paste_detector and run["tool_version"] == "0.16.0"
    assert not run["diagnostics"]
    assert later["detector_coverage"]["detectors"][paste_detector]["status"] == "partial"
    assert later["source_parsing"]["parsing_status"] == {"partial": 1}
    print("T4 source-bound rescan verification passed: curl exact diff; pasteboard legacy candidates; later snapshot remains partial.")


if __name__ == "__main__":
    main()
