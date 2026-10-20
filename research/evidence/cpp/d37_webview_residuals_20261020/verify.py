#!/usr/bin/env python3
"""Verify the source-derived D37 webview residual replay projections."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


RULE = "ohcpp-memory-bounds-vector-index-candidate-005"
VULNERABLE_ROOT = {85, 87, 96, 98, 140, 142}
VULNERABLE_RESIDUAL = {116, 118, 126, 127, 131, 133}
FIXED_RESIDUAL = {122, 124, 132, 133, 137, 139}


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def check(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", type=Path, default=Path(__file__).parent)
    args = parser.parse_args()
    evidence = args.evidence_dir
    reports = {side: load(evidence / f"{side}.json") for side in ("vulnerable", "fixed")}

    for side, report in reports.items():
        check(report["repository"] == "openharmony/web_webview", f"{side}: repository")
        check(report["status"] == "completed_with_limitations", f"{side}: aggregate status")
        check(report["detector_count"] == 1, f"{side}: detector count")
        run, = report["detector_runs"]
        check(run["tool"] == "ohscanner.cpp.bounds", f"{side}: detector ID")
        check(run["tool_version"] == "0.3.0", f"{side}: detector version")
        check(run["status"] == "blocked", f"{side}: partial control must block aggregate")
        for diagnostic in run["diagnostics"]:
            check(diagnostic["rule_id"] == RULE, f"{side}: unexpected rule ID")
            occurrence = diagnostic["finding_identity"]["occurrence"]["basis"]
            check(occurrence["rule_version"] == "0.1.0", f"{side}: rule version")
        parsing = {item["file"]: item["status"] for item in run["parsing"]}
        check(parsing.get("partial.cpp") == "partial", f"{side}: partial control status")
        for control in ("safe.cpp", "unrelated.cpp"):
            check(not any(d["file"] == control for d in run["diagnostics"]), f"{side}: {control} must be quiet")
        check(sum(d["file"] == "renamed.cpp" and d["line"] == 3 for d in run["diagnostics"]) == 1,
              f"{side}: renamed positive")

    vuln = reports["vulnerable"]["detector_runs"][0]["diagnostics"]
    fixed = reports["fixed"]["detector_runs"][0]["diagnostics"]
    vuln_root = {d["line"] for d in vuln if d["file"] == "vulnerable_flowbuffer_functions.cc" and d["line"] in VULNERABLE_ROOT}
    vuln_residual = {d["line"] for d in vuln if d["file"] == "vulnerable_flowbuffer_functions.cc" and d["line"] in VULNERABLE_RESIDUAL}
    fixed_residual = {d["line"] for d in fixed if d["file"] == "fixed_flowbuffer_functions.cc"}
    check(vuln_root == VULNERABLE_ROOT, "vulnerable patched-root locations")
    check(vuln_residual == VULNERABLE_RESIDUAL, "vulnerable ordinary residual locations")
    check(fixed_residual == FIXED_RESIDUAL, "fixed ordinary residual locations")
    check(not any(d["file"] == "fixed_flowbuffer_functions.cc" and d["line"] in VULNERABLE_ROOT for d in fixed),
          "fixed patched-root sites must be quiet")
    check(reports["vulnerable"]["diagnostic_count"] == 13, "vulnerable total")
    check(reports["fixed"]["diagnostic_count"] == 7, "fixed total")
    print("PASS D37: exact-fragment CLI projections; 6 vulnerable roots / 0 fixed roots; 6 ordinary residuals on each side; renamed positive; safe/unrelated quiet; partial aggregate retained")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
