from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path


HERE = Path(__file__).resolve().parent
BASE = "983afb846ceaa34daf690c39e4918703c4ac99a7"
VULN_ROOT_LINES = [85, 87, 96, 98, 140, 142]
ORDINARY_VULN_LINES = [116, 118, 126, 127, 131, 133]
ORDINARY_FIXED_LINES = [122, 124, 132, 133, 137, 139]


def read_report(name: str) -> dict:
    return json.loads((HERE / name).read_text(encoding="utf-8"))


def findings(report: dict, path: str) -> list[dict]:
    return [
        {
            "file": item["file"],
            "line": item["line"],
            "symbol": item["symbol"],
            "rule_id": item["rule_id"],
            "rule_version": item["finding_identity"]["observation"]["rule_version"],
            "source_sha256": item["source_sha256"],
        }
        for item in report["detector_runs"][0]["diagnostics"]
        if item["file"] == path
    ]


def main() -> None:
    identities = json.loads((HERE / "source-identities.json").read_text(encoding="utf-8"))
    vuln = read_report("current-vulnerable.json")
    fixed = read_report("current-fixed.json")
    full_vuln = read_report("current-full-vulnerable.json")
    full_fixed = read_report("current-full-fixed.json")
    baseline_vuln = read_report("baseline-vulnerable.json")
    baseline_fixed = read_report("baseline-fixed.json")
    vuln_source = findings(vuln, "flowbuffer_functions.cc")
    fixed_source = findings(fixed, "flowbuffer_functions.cc")
    vuln_root = [item for item in vuln_source if item["line"] in VULN_ROOT_LINES]
    vuln_ordinary = [item for item in vuln_source if item["line"] in ORDINARY_VULN_LINES]
    fixed_root = [item for item in fixed_source if item["line"] not in ORDINARY_FIXED_LINES]
    fixed_ordinary = [item for item in fixed_source if item["line"] in ORDINARY_FIXED_LINES]
    controls_vuln = {
        name: findings(vuln, name)
        for name in ("safe.cpp", "unrelated.cpp", "renamed.cpp", "partial.cpp")
    }
    controls_fixed = {
        name: findings(fixed, name)
        for name in ("safe.cpp", "unrelated.cpp", "renamed.cpp", "partial.cpp")
    }
    if len(vuln_root) != 6 or len(vuln_ordinary) != 6:
        raise SystemExit("vulnerable source finding classification changed; review required")
    if fixed_root or len(fixed_ordinary) != 6:
        raise SystemExit("fixed source root/residual classification changed; review required")
    if controls_vuln["safe.cpp"] or controls_vuln["unrelated.cpp"]:
        raise SystemExit("safe or unrelated control unexpectedly reported")
    if controls_vuln["renamed.cpp"] != controls_fixed["renamed.cpp"] or len(controls_vuln["renamed.cpp"]) != 1:
        raise SystemExit("renamed positive control did not remain stable")
    if controls_vuln["partial.cpp"] or controls_fixed["partial.cpp"]:
        raise SystemExit("partial control unexpectedly emitted a finding")
    for report in (full_vuln, full_fixed):
        run = report["detector_runs"][0]
        if report["source_parsing"]["parsing_status"] != {"partial": 1} or run["status"] != "blocked" or run["diagnostic_count"] != 0:
            raise SystemExit("full TU must remain partial/blocked with zero diagnostics")
    for report in (baseline_vuln, baseline_fixed):
        run = report["detector_runs"][0]
        if run["tool_version"] != "0.2.0" or run["diagnostic_count"] != 0:
            raise SystemExit("frozen integration baseline must remain a 0.2.0 zero-finding replay")
    base_bounds_blob = subprocess.check_output(
        ["git", "rev-parse", f"{BASE}:src/ohscanner/detectors/cpp/bounds_detector.py"],
        text=True,
    ).strip()
    current_bounds_sha256 = hashlib.sha256(
        Path("src/ohscanner/detectors/cpp/bounds_detector.py").read_bytes()
    ).hexdigest()
    result = {
        "schema_version": 1,
        "case_id": "web_webview-CVE-2026-27648-D11",
        "base_commit": BASE,
        "source_identity_manifest": "source-identities.json",
        "source_identity_manifest_sha256": hashlib.sha256((HERE / "source-identities.json").read_bytes()).hexdigest(),
        "pre_change_bounds_detector_blob": base_bounds_blob,
        "current_bounds_detector_sha256": current_bounds_sha256,
        "detector": {
            "id": "ohscanner.cpp.bounds",
            "version": "0.3.0",
            "new_rule_id": "ohcpp-memory-bounds-vector-index-candidate-005",
            "new_rule_version": "0.1.0",
            "scope": "Only syntactically declared std::vector dynamic subscripts; suppresses only an exact same-loop vector size/constructor-capacity bound with local nonnegative index evidence.",
        },
        "baseline_cli": {
            "vulnerable": {
                "detector_version": baseline_vuln["detector_runs"][0]["tool_version"],
                "status": baseline_vuln["detector_runs"][0]["status"],
                "diagnostic_count": baseline_vuln["detector_runs"][0]["diagnostic_count"],
                "parse_status": baseline_vuln["source_parsing"]["parsing_status"],
                "report": "baseline-vulnerable.json",
            },
            "fixed": {
                "detector_version": baseline_fixed["detector_runs"][0]["tool_version"],
                "status": baseline_fixed["detector_runs"][0]["status"],
                "diagnostic_count": baseline_fixed["detector_runs"][0]["diagnostic_count"],
                "parse_status": baseline_fixed["source_parsing"]["parsing_status"],
                "report": "baseline-fixed.json",
            },
        },
        "fragment_cli": {
            "commands": [
                "python -m src.cli ohscan-run --repo-dir D:/openHarmonyScanner/tmp/d11-webview-flowbuffer-fragments-20261020-v2 --repository OpenHarmony-TPC/chromium_src --commit 769110ddf1c14355c89f34b974ab9e6cf58c0c6c --include flowbuffer_functions.cc --include safe.cpp --include unrelated.cpp --include renamed.cpp --include partial.cpp --detector ohscanner.cpp.bounds --json-out research/evidence/cpp/d11_webview_fragment_20261020/current-vulnerable.json --md-out research/evidence/cpp/d11_webview_fragment_20261020/current-vulnerable.md",
                "python -m src.cli ohscan-run --repo-dir D:/openHarmonyScanner/tmp/d11-webview-flowbuffer-fragments-20261020-v2 --repository OpenHarmony-TPC/chromium_src --commit f550e8e59c57afe4e02b130ec3373b1011843617 --include flowbuffer_functions.cc --include safe.cpp --include unrelated.cpp --include renamed.cpp --include partial.cpp --detector ohscanner.cpp.bounds --json-out research/evidence/cpp/d11_webview_fragment_20261020/current-fixed.json --md-out research/evidence/cpp/d11_webview_fragment_20261020/current-fixed.md",
            ],
            "vulnerable": {
                "synthetic_commit": identities["snapshots"]["vulnerable"]["synthetic_commit"],
                "status": vuln["detector_runs"][0]["status"],
                "parse_status": vuln["source_parsing"]["parsing_status"],
                "elapsed_seconds": vuln["detector_runs"][0]["elapsed_seconds"],
                "diagnostic_count_all_files": vuln["detector_runs"][0]["diagnostic_count"],
                "flowbuffer_root_specific": vuln_root,
                "ordinary_argument_loop_residual": vuln_ordinary,
                "controls": controls_vuln,
            },
            "fixed": {
                "synthetic_commit": identities["snapshots"]["fixed"]["synthetic_commit"],
                "status": fixed["detector_runs"][0]["status"],
                "parse_status": fixed["source_parsing"]["parsing_status"],
                "elapsed_seconds": fixed["detector_runs"][0]["elapsed_seconds"],
                "diagnostic_count_all_files": fixed["detector_runs"][0]["diagnostic_count"],
                "flowbuffer_root_specific": fixed_root,
                "ordinary_argument_loop_residual": fixed_ordinary,
                "controls": controls_fixed,
            },
            "reports": [
                "current-vulnerable.json", "current-vulnerable.md",
                "current-fixed.json", "current-fixed.md",
            ],
        },
        "full_translation_unit_cli": {
            "commands": [
                "python -m src.cli ohscan-run --repo-dir D:/openHarmonyScanner/tmp/web-webview-flowbuf-full-tu-m2-20261019 --repository OpenHarmony-TPC/chromium_src --commit a15cbf4ef20673cfcf1856bf40a723b3ce026564 --include arkweb/ohos_nweb/src/cef_delegate/nweb_handler_delegate.cc --detector ohscanner.cpp.bounds --json-out research/evidence/cpp/d11_webview_fragment_20261020/current-full-vulnerable.json --md-out research/evidence/cpp/d11_webview_fragment_20261020/current-full-vulnerable.md",
                "python -m src.cli ohscan-run --repo-dir D:/openHarmonyScanner/tmp/web-webview-flowbuf-full-tu-m2-20261019 --repository OpenHarmony-TPC/chromium_src --commit fa0d92ccbf47b7cdc7efb727c79cbdfc168469eb --include arkweb/ohos_nweb/src/cef_delegate/nweb_handler_delegate.cc --detector ohscanner.cpp.bounds --json-out research/evidence/cpp/d11_webview_fragment_20261020/current-full-fixed.json --md-out research/evidence/cpp/d11_webview_fragment_20261020/current-full-fixed.md",
            ],
            "vulnerable": {
                "synthetic_commit": "a15cbf4ef20673cfcf1856bf40a723b3ce026564",
                "source_sha256": "aa401c305ed30b70007917d97b726986a26aff2d00fb49649466533f4a48a920",
                "parse_status": full_vuln["source_parsing"]["parsing_status"],
                "detector_status": full_vuln["detector_runs"][0]["status"],
                "diagnostic_count": full_vuln["detector_runs"][0]["diagnostic_count"],
                "elapsed_seconds": full_vuln["detector_runs"][0]["elapsed_seconds"],
            },
            "fixed": {
                "synthetic_commit": "fa0d92ccbf47b7cdc7efb727c79cbdfc168469eb",
                "source_sha256": "332a66637fef9c669fdb85dd74c9be861fb01adb8fa8a95871e1a407e9210483",
                "parse_status": full_fixed["source_parsing"]["parsing_status"],
                "detector_status": full_fixed["detector_runs"][0]["status"],
                "diagnostic_count": full_fixed["detector_runs"][0]["diagnostic_count"],
                "elapsed_seconds": full_fixed["detector_runs"][0]["elapsed_seconds"],
            },
            "reports": [
                "current-full-vulnerable.json", "current-full-vulnerable.md",
                "current-full-fixed.json", "current-full-fixed.md",
            ],
        },
        "t7_v0_3_6_reconciliation": {
            "diagnostic_map": "D:/openHarmonyScanner/CyberSecurity-Innovation-Audit/research/evidence/cpp/web_webview_cve_2026_27648_20261019/root-cause-diagnostic-map-v036.json",
            "diagnostic_map_sha256": "a78a9de64f2d5376a89271125e7d5ff4fc8ecd2dea4871dd6364c3e8b1c4be00",
            "result": "T7's 12/6 function-fragment counts divide into six patched-loop findings on vulnerable / zero at those fixed sites plus six ordinary argument-loop findings on each side. D11 reproduces this division using the current integration lineage as a separately versioned candidate-005 rule. The residuals remain candidates because constructor-size and signed narrowing/cross-loop invariants are not fully proven.",
        },
        "disposition": "PARTIAL: root-specific complete-function fragment differential passes with controls; full translation units remain partial/blocked; residual ordinary-loop candidates remain unresolved; no product build/reachability/impact validation.",
    }
    (HERE / "replay.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "baseline": [baseline_vuln["detector_runs"][0]["diagnostic_count"], baseline_fixed["detector_runs"][0]["diagnostic_count"]],
        "vulnerable": {"diagnostics": len(vuln_source), "root": len(vuln_root), "ordinary": len(vuln_ordinary)},
        "fixed": {"diagnostics": len(fixed_source), "root": len(fixed_root), "ordinary": len(fixed_ordinary)},
        "full_tu": [full_vuln["detector_runs"][0]["status"], full_fixed["detector_runs"][0]["status"]],
    }, indent=2))


if __name__ == "__main__":
    main()
