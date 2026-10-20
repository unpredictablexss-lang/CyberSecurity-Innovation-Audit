from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent / "t_matrix_webview_libtiff_20261030"


def read(name: str) -> dict:
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def check(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def main() -> None:
    identities = read("webview-source-identities.json")
    source_check = read("webview-source-identity-check.json")
    check(identities["case"] == "web_webview-CVE-2026-27648-D11", "webview case identity")
    check(source_check["source_path"] == identities["source_path"], "webview source path binding")
    verified_by_role = {row["variant"]: row for row in source_check["results"]}
    for role in ("vulnerable", "fixed"):
        pinned = identities["snapshots"][role]
        verified = verified_by_role[role]
        for field in ("commit", "tree", "blob", "sha256", "bytes"):
            actual_field = "source_sha256" if field == "sha256" else "source_bytes" if field == "bytes" else field
            check(verified[actual_field] == pinned[field], f"{role} upstream {field} identity")
        check(verified["identity_and_fragment_match"] is True, f"{role} exact function fragment binding")

    webview_expected = {
        "webview-fragment-vuln.json": ("769110ddf1c14355c89f34b974ab9e6cf58c0c6c", 13, 4, 1),
        "webview-fragment-fixed.json": ("f550e8e59c57afe4e02b130ec3373b1011843617", 7, 4, 1),
    }
    web_counts: dict[str, int] = {}
    for filename, (commit, count, complete, partial) in webview_expected.items():
        report = read(filename)
        run = report["detector_runs"][0]
        check(report["commit"] == commit, f"{filename} snapshot commit")
        check(run["tool"] == "ohscanner.cpp.bounds" and run["tool_version"] == "0.3.0", f"{filename} detector version")
        check(run["diagnostic_count"] == count and len(run["diagnostics"]) == count, f"{filename} finding count")
        check(run["status"] == "blocked", f"{filename} partial control must block aggregate coverage")
        parsing = report["source_parsing"]["parsing_status"]
        check(parsing == {"complete": complete, "partial": partial}, f"{filename} parse status")
        ids = [item["rule_id"] for item in run["diagnostics"]]
        check(set(ids) == {"ohcpp-memory-bounds-vector-index-candidate-005"}, f"{filename} rule identity")
        files = {item["file"] for item in run["diagnostics"]}
        check("safe.cpp" not in files and "unrelated.cpp" not in files and "partial.cpp" not in files, f"{filename} safe/unrelated/partial controls stay quiet")
        web_counts[filename] = count
    vuln_ids = [d["symbol"] for d in read("webview-fragment-vuln.json")["detector_runs"][0]["diagnostics"]]
    fixed_ids = [d["symbol"] for d in read("webview-fragment-fixed.json")["detector_runs"][0]["diagnostics"]]
    check([d["line"] for d in read("webview-fragment-vuln.json")["detector_runs"][0]["diagnostics"][:6]] == [85, 87, 96, 98, 116, 118], "six vulnerable patched-root locations")
    check([d["line"] for d in read("webview-fragment-fixed.json")["detector_runs"][0]["diagnostics"][:6]] == [122, 124, 132, 133, 137, 139], "six fixed-side ordinary residual locations")
    check(vuln_ids.count("renamed_items") == 1 and fixed_ids.count("renamed_items") == 1, "renamed positive control")

    for filename, commit, tree, blob, sha in (
        ("libtiff-full-vuln.json", "9dff73bebc5661f2dace6f16e14cf9e857172f4e", "986499c84247e9a1f49560128bbe7580d8ebea1a", "6c7b5031a1937bb48cc79808a59618d8a4f6237e", "cf39474735eba839a097a540fbc3f5f17791d6f7496a1800e04dbefc0e7d13e3"),
        ("libtiff-full-fixed.json", "3e0dcf0ec651638b2bd849b2e6f3124b36890d99", "77361ef7262189e16a2010b5c333f6b275d17f09", "2774caa0eef24bce2a619d2686a23d59fb5ef9db", "de1bb87b9c2882c73f1045d9510e30d997afb48c52179a62b647aed4c6cee7d8"),
    ):
        report = read(filename)
        run = report["detector_runs"][0]
        check(report["commit"] == commit, f"{filename} pinned commit")
        check(report["git_tree"] == tree, f"{filename} pinned tree")
        check(run["tool"] == "ohscanner.cpp.bounds" and run["tool_version"] == "0.3.0", f"{filename} detector version")
        check(report["source_parsing"]["parsing_status"] == {"partial": 2}, f"{filename} partial parse")
        check(run["status"] == "blocked" and run["diagnostic_count"] == 0, f"{filename} blocked zero result")

    probe = read("libtiff-function-probe.json")["function_fragment_probe"]
    v, f = probe["vulnerable"], probe["fixed"]
    for role, result, tree, blob, sha in (
        ("vulnerable", v, "986499c84247e9a1f49560128bbe7580d8ebea1a", "6c7b5031a1937bb48cc79808a59618d8a4f6237e", "cf39474735eba839a097a540fbc3f5f17791d6f7496a1800e04dbefc0e7d13e3"),
        ("fixed", f, "77361ef7262189e16a2010b5c333f6b275d17f09", "2774caa0eef24bce2a619d2686a23d59fb5ef9db", "de1bb87b9c2882c73f1045d9510e30d997afb48c52179a62b647aed4c6cee7d8"),
    ):
        check(result["tree"] == tree and result["blob"] == blob and result["file_sha256"] == sha, f"libtiff {role} source binding")
    check(v["function"]["function_parse"] == "complete" and f["function"]["function_parse"] == "complete", "libtiff bounded parse")
    check(v["detector"]["id"] == "ohscanner.cpp.bounds" and v["detector"]["version"] == "0.3.0", "libtiff probe detector version")
    check(len(v["detector"]["findings"]) == 1 and len(f["detector"]["findings"]) == 0, "libtiff function vulnerable/fixed differential")
    finding = v["detector"]["findings"][0]
    check(finding["rule_id"] == "ohcpp-memory-bounds-pointer-offset-candidate-004" and finding["original_function_line"] == 621, "libtiff candidate location")

    matrix = (ROOT / "README.md").read_text(encoding="utf-8")
    check("3 PASS / 8 PARTIAL / 2 N/A" in matrix, "preserved T2/T12 matrix count")
    check("PARTIAL/BLOCK" in matrix and "not a safe/fixed conclusion" in matrix, "partial limitations retained")
    print("T matrix webview/libtiff source identities, current CLI evidence, controls, coverage, and matrix disposition: PASS")


if __name__ == "__main__":
    main()
