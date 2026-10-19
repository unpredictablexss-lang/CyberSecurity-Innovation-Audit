"""Replay CVE-2026-27648 on pinned pre-fix and fixed OpenHarmony WebView commits."""
import argparse, hashlib, json, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.known_cves import KnownDisclosedCveDetector
from src.ohscanner.fixture import snapshot_digest

REPO = "openharmony-tpc/chromium_src"
BRANCH_SNAPSHOT = "6539ea501a7a2bac6aa0825bb9180443b864b0c1"
VULNERABLE_COMMIT = "a2de9fedca08d339593849732aceacbc72cebc4c"
VULNERABLE_TREE = "aa962f036b96bbca53e5bc1d711f99b233f5806e"
VULNERABLE_BLOB = "78e83fea67a2db3297cc59f07566a0c0b6153e7a"
VULNERABLE_SHA = "aa401c305ed30b70007917d97b726986a26aff2d00fb49649466533f4a48a920"
FIX_COMMIT = "18c5ba4d75a909c8736e0e45355f358860e47778"
FIX_TREE = "a7769bf612be457e6e368f14ee355f3ea8ed2935"
FIX_BLOB = "27e93e338ced03aeed6e7d892e29d4d0740f3653"
FIX_SHA = "332a66637fef9c669fdb85dd74c9be861fb01adb8fa8a95871e1a407e9210483"
PATH = "arkweb/ohos_nweb/src/cef_delegate/nweb_handler_delegate.cc"


def git_bytes(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def git_text(repo, *args):
    return git_bytes(repo, *args).decode("utf-8").strip()


def is_ancestor(repo, ancestor, descendant):
    return subprocess.run(["git", "-C", str(repo), "merge-base", "--is-ancestor",
        ancestor, descendant], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def scan(text, commit, variant):
    unit = SourceUnit(PATH, "cpp", text, hashlib.sha256(text.encode()).hexdigest(),
                      parse_status="not_run")
    request = ScanRequest("d28:" + variant, REPO, commit, snapshot_digest((unit,)),
        "current-component:" + REPO, profile_id="fixture-no-build", provenance="fixture")
    run = KnownDisclosedCveDetector().detect(ScanContext(request, (unit,)), (unit,))
    findings = [{"rule_id": f.rule_id, "symbol": f.symbol, "line": f.line,
        "source_sha256": f.source_sha256, "message": f.message}
        for f in run.findings if f.symbol == "CVE-2026-27648"]
    return unit, run, findings


def source_for(repo, commit, tree, blob, expected_sha):
    actual_tree = git_text(repo, "rev-parse", commit + "^{tree}")
    actual_blob = git_text(repo, "rev-parse", commit + ":" + PATH)
    if (actual_tree, actual_blob) != (tree, blob):
        raise SystemExit("commit/tree/blob mismatch for " + commit)
    raw = git_bytes(repo, "show", commit + ":" + PATH)
    actual_sha = hashlib.sha256(raw).hexdigest()
    if actual_sha != expected_sha:
        raise SystemExit("source SHA-256 mismatch for " + commit)
    return raw.decode("utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-dir", type=Path, required=True,
                        help="local Git object store; this script never fetches")
    parser.add_argument("--output", type=Path,
        default=Path(__file__).with_name("D28_WEBVIEW_CVE_2026_27648_REPLAY.json"))
    args = parser.parse_args()
    if not is_ancestor(args.repo_dir, VULNERABLE_COMMIT, FIX_COMMIT):
        raise SystemExit("pre-fix commit is not an ancestor of the fix commit")
    if not is_ancestor(args.repo_dir, FIX_COMMIT, BRANCH_SNAPSHOT):
        raise SystemExit("fix commit is not an ancestor of the pinned 6.0 release branch snapshot")
    old = source_for(args.repo_dir, VULNERABLE_COMMIT, VULNERABLE_TREE,
                     VULNERABLE_BLOB, VULNERABLE_SHA)
    fixed = source_for(args.repo_dir, FIX_COMMIT, FIX_TREE, FIX_BLOB, FIX_SHA)
    old_unit, old_run, old_findings = scan(old, VULNERABLE_COMMIT, "official_6_0_prefx_source")
    fix_unit, fix_run, fix_findings = scan(fixed, FIX_COMMIT, "official_6_0_fixed_source")
    if len(old_findings) != 1 or fix_findings:
        raise SystemExit("expected one pre-fix candidate and zero fixed candidates")
    result = {
        "schema": 1, "repository": REPO, "path": PATH,
        "branch_snapshot": BRANCH_SNAPSHOT,
        "branch_history": {
            "pre_fix_commit": VULNERABLE_COMMIT, "pre_fix_is_ancestor_of_fix": True,
            "fix_commit": FIX_COMMIT, "fix_is_ancestor_of_branch_snapshot": True
        },
        "pre_fix": {"tree": VULNERABLE_TREE, "blob": VULNERABLE_BLOB,
            "source_sha256": old_unit.sha256, "parse_status": "not_run",
            "run_status": old_run.status, "candidate_count": len(old_findings),
            "candidate": old_findings[0]},
        "fixed": {"tree": FIX_TREE, "blob": FIX_BLOB,
            "source_sha256": fix_unit.sha256, "parse_status": "not_run",
            "run_status": fix_run.status, "candidate_count": len(fix_findings)},
        "detector": KnownDisclosedCveDetector.detector_id,
        "detector_version": KnownDisclosedCveDetector.version,
        "classification": "pre-fix/fixed upstream component source regression; product status remains unknown",
        "validated_vulnerability": 0,
        "limitations": [
            "The positive is a real pre-fix commit in the pinned 6.0 release branch history, not a reconstructed source.",
            "Parser is not run, so both executions remain blocked.",
            "No OpenHarmony product build, remote input reachability, runtime exploit, or product impact was tested."
        ]
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "pre_fix_commit": VULNERABLE_COMMIT,
        "fix_commit": FIX_COMMIT, "pre_fix_candidates": len(old_findings),
        "fixed_candidates": len(fix_findings), "candidate_line": old_findings[0]["line"],
        "validated_vulnerability": 0}, ensure_ascii=False))


if __name__ == "__main__":
    main()
