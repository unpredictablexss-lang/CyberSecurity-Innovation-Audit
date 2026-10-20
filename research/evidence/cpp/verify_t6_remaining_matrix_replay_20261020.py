from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


EVIDENCE = Path(__file__).resolve().parent / "t6_remaining_matrix_replay_20261020"
SCANNER_COMMIT = "81dd4aea9bb51522ac912b33504ef0d2ddb79089"


def check(ok: bool, message: str) -> None:
    if not ok:
        raise SystemExit(f"FAIL: {message}")


def git(repo: Path, *args: str, text: bool = True) -> str | bytes:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=text,
        encoding="utf-8" if text else None,
    )
    return result.stdout.strip() if text else result.stdout


def read_json(name: str) -> dict:
    return json.loads((EVIDENCE / name).read_text(encoding="utf-8"))


def check_source_object(repo: Path, commit: str, tree: str, files: dict[str, dict]) -> None:
    check(git(repo, "rev-parse", commit) == commit, f"source commit exists: {commit}")
    check(git(repo, "rev-parse", f"{commit}^{{tree}}") == tree, f"tree binding: {commit}")
    for path, identity in files.items():
        blob = git(repo, "rev-parse", f"{commit}:{path}")
        content = git(repo, "show", f"{commit}:{path}", text=False)
        check(blob == identity["blob"], f"blob binding: {commit}:{path}")
        check(hashlib.sha256(content).hexdigest() == identity["sha256"], f"SHA-256 binding: {commit}:{path}")


def check_report(name: str, commit: str, tree: str, scope: list[str], count: int, parse: dict[str, int], tool_version: str = "0.3.0") -> dict:
    report = read_json(name)
    check(report["commit"] == commit and report["git_tree"] == tree, f"{name} source commit/tree")
    check(report["scope"]["declared_scope"] == scope, f"{name} exact scope")
    check(report["source_parsing"]["parsing_status"] == parse, f"{name} parser status")
    run = report["detector_runs"][0]
    check(run["tool"] == "ohscanner.cpp.bounds" and run["tool_version"] == tool_version, f"{name} detector/version")
    check(run["diagnostic_count"] == count and len(run["diagnostics"]) == count, f"{name} findings")
    check(run["status"] == "blocked", f"{name} must retain blocked coverage")
    source_hashes = report["detector_coverage"]["detectors"]["ohscanner.cpp.bounds"]["source_sha256"]
    for item in report["audit_plan"]["source"]["files"]:
        check(source_hashes[item["path"]] == item["sha256"], f"{name} file source SHA projection")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--libtiff-repo", type=Path, default=Path("D:/openHarmonyScanner/tmp/libtiff-cve-2025-9900-upstream"))
    parser.add_argument("--webview-upstream-mirror", type=Path, default=Path("D:/openHarmonyScanner/tmp/chromium-src-cve-2026-27648-audit.git"))
    parser.add_argument("--webview-fragment-repo", type=Path, default=Path("D:/openHarmonyScanner/tmp/d11-webview-flowbuffer-fragments-20261020-v2"))
    parser.add_argument("--scanner-repo", type=Path, default=Path(__file__).resolve().parents[3])
    args = parser.parse_args()

    check(git(args.scanner_repo, "cat-file", "-t", SCANNER_COMMIT) == "commit", "frozen scanner commit exists")
    check(subprocess.run(["git", "-C", str(args.scanner_repo), "merge-base", "--is-ancestor", SCANNER_COMMIT, "HEAD"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0, "frozen scanner commit is an ancestor of evidence checkout")
    check(subprocess.run(["git", "-C", str(args.scanner_repo), "diff", "--quiet", SCANNER_COMMIT, "HEAD", "--", "src"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0, "scanner implementation is unchanged since frozen baseline")
    ids = read_json("source-identities.json")
    check(ids["scanner_commit"] == SCANNER_COMMIT, "manifest scanner pin")

    lib = ids["libtiff"]
    for role in ("vulnerable", "fixed"):
        source = lib[role]
        check_source_object(args.libtiff_repo, source["commit"], source["tree"], source["files"])
    lv = check_report("libtiff-vuln.json", lib["vulnerable"]["commit"], lib["vulnerable"]["tree"], lib["scope"], 0, {"partial": 2})
    lf = check_report("libtiff-fixed.json", lib["fixed"]["commit"], lib["fixed"]["tree"], lib["scope"], 0, {"partial": 2})
    for report in (lv, lf):
        check(report["detector_coverage"]["detectors"]["ohscanner.cpp.bounds"]["status"] == "blocked", "libtiff semantic coverage remains blocked")

    web = ids["webview"]
    source_check = read_json("webview-source-identity-check.json")
    source_ids = read_json("webview-source-identities.json")
    check(source_check["source_path"] == web["source_path"] == source_ids["source_path"], "webview upstream path binding")
    verified = {row["variant"]: row for row in source_check["results"]}
    for role in ("vulnerable", "fixed"):
        source = web[role]
        prior = source_ids["snapshots"][role]
        identity = verified[role]
        for current, historic, checked in (("source_commit", "commit", "commit"), ("source_tree", "tree", "tree"), ("source_blob", "blob", "blob"), ("source_sha256", "sha256", "source_sha256")):
            check(source[current] == prior[historic] == identity[checked], f"webview upstream {role} {current}")
        check(identity["identity_and_fragment_match"] is True, f"upstream-to-fragment source check: {role}")
        check(git(args.webview_upstream_mirror, "rev-parse", source["source_commit"]) == source["source_commit"], f"webview source commit exists: {role}")
        check(git(args.webview_upstream_mirror, "rev-parse", f"{source['source_commit']}^{{tree}}") == source["source_tree"], f"webview source tree: {role}")
        upstream_bytes = git(args.webview_upstream_mirror, "show", f"{source['source_commit']}:{web['source_path']}", text=False)
        check(git(args.webview_upstream_mirror, "rev-parse", f"{source['source_commit']}:{web['source_path']}") == source["source_blob"], f"webview source blob: {role}")
        check(hashlib.sha256(upstream_bytes).hexdigest() == source["source_sha256"], f"webview full source SHA: {role}")
        fragment_commit = source["fragment_commit"]
        check(git(args.webview_fragment_repo, "rev-parse", fragment_commit) == fragment_commit, f"fragment commit exists: {role}")
        check(git(args.webview_fragment_repo, "rev-parse", f"{fragment_commit}^{{tree}}") == source["fragment_tree"], f"fragment tree: {role}")
        fragment_bytes = git(args.webview_fragment_repo, "show", f"{fragment_commit}:flowbuffer_functions.cc", text=False)
        check(hashlib.sha256(fragment_bytes).hexdigest() == source["fragment_sha256"], f"webview fragment SHA: {role}")

    for name in ("webview-vuln.json", "webview-fixed.json"):
        report = read_json(name)
        check(report["scope"]["declared_scope"] == web["scope"], f"{name} exact five-file scope")
        check(report["detector_runs"][0]["tool_version"] == "0.3.0", f"{name} rule version")
        check(report["source_parsing"]["parsing_status"] == {"complete": 4, "partial": 1}, f"{name} parse coverage")
        check(report["detector_runs"][0]["status"] == "blocked", f"{name} partial control blocks aggregate")
        report_files = {row["path"]: row for row in report["audit_plan"]["source"]["files"]}
        for path in web["scope"]:
            blob = git(args.webview_fragment_repo, "rev-parse", f"{report['commit']}:{path}")
            content = git(args.webview_fragment_repo, "show", f"{report['commit']}:{path}", text=False)
            check(blob == report_files[path]["blob_oid"], f"{name} synthetic snapshot blob: {path}")
            check(hashlib.sha256(content).hexdigest() == report_files[path]["sha256"], f"{name} synthetic snapshot SHA: {path}")
            check(report["detector_coverage"]["detectors"]["ohscanner.cpp.bounds"]["source_sha256"][path] == report_files[path]["sha256"], f"{name} coverage source SHA: {path}")

    web_v = check_report("webview-vuln.json", web["vulnerable"]["fragment_commit"], web["vulnerable"]["fragment_tree"], web["scope"], 13, {"complete": 4, "partial": 1})
    web_f = check_report("webview-fixed.json", web["fixed"]["fragment_commit"], web["fixed"]["fragment_tree"], web["scope"], 7, {"complete": 4, "partial": 1})
    rule_ids_v = [row["rule_id"] for row in web_v["detector_runs"][0]["diagnostics"]]
    rule_ids_f = [row["rule_id"] for row in web_f["detector_runs"][0]["diagnostics"]]
    check(set(rule_ids_v + rule_ids_f) == {"ohcpp-memory-bounds-vector-index-candidate-005"}, "webview finding rule identity")
    lines_v = [row["line"] for row in web_v["detector_runs"][0]["diagnostics"][:6]]
    lines_f = [row["line"] for row in web_f["detector_runs"][0]["diagnostics"][:6]]
    check(lines_v == [85, 87, 96, 98, 116, 118], "webview vulnerable root locations")
    check(lines_f == [122, 124, 132, 133, 137, 139], "webview fixed-side residual locations")
    for report in (web_v, web_f):
        files = {row["file"] for row in report["detector_runs"][0]["diagnostics"]}
        check("safe.cpp" not in files and "unrelated.cpp" not in files and "partial.cpp" not in files, "safe/unrelated/partial controls quiet")

    print("T6 remaining matrix source-bound CLI replay: PASS (evidence integrity); case outcomes remain PARTIAL/BLOCK")


if __name__ == "__main__":
    main()

