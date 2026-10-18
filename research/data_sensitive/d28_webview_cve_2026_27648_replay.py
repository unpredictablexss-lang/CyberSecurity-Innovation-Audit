"""Replay CVE-2026-27648 on a pinned fix blob and an in-memory reverse-fix control."""
import argparse, hashlib, json, re, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.known_cves import KnownDisclosedCveDetector
from src.ohscanner.fixture import snapshot_digest

REPO = "openharmony-tpc/chromium_src"
COMMIT = "18c5ba4d75a909c8736e0e45355f358860e47778"
TREE = "a7769bf612be457e6e368f14ee355f3ea8ed2935"
BLOB = "27e93e338ced03aeed6e7d892e29d4d0740f3653"
PATH = "arkweb/ohos_nweb/src/cef_delegate/nweb_handler_delegate.cc"
FIXED_SHA = "332a66637fef9c669fdb85dd74c9be861fb01adb8fa8a95871e1a407e9210483"


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode("utf-8").strip()


def scan(text, variant):
    unit = SourceUnit(PATH, "cpp", text, hashlib.sha256(text.encode()).hexdigest(),
                      parse_status="not_run")
    request = ScanRequest("d28:" + variant, REPO, COMMIT, snapshot_digest((unit,)),
        "current-component:" + REPO, profile_id="fixture-no-build", provenance="fixture")
    run = KnownDisclosedCveDetector().detect(ScanContext(request, (unit,)), (unit,))
    findings = [{"rule_id": f.rule_id, "symbol": f.symbol, "line": f.line,
        "source_sha256": f.source_sha256, "message": f.message}
        for f in run.findings if f.symbol == "CVE-2026-27648"]
    return unit, run, findings


def reverse_fix(text):
    text, n_guard = re.subn(
        r"(?ms)^\s*if\s*\(\s*\(\s*offset\s*\+\s*\*strLen\s*\)"
        r"\s*>\s*MAX_FLOWBUF_DATA_SIZE\s*\)\s*\{.*?^\s*\}", "", text)
    text, n_size = re.subn(
        r"(?m)^\s*int\s+dataListSize\s*=\s*argsSize\s*\+\s*flowbufSize\s*;\s*\n", "", text)
    text, n_loop = re.subn(
        r"while\s*\(\s*curIndex\s*<\s*dataListSize\s*&&\s*argIndex\s*==\s*curIndex\s*\)",
        "while (argIndex == curIndex)", text)
    if (n_guard, n_size, n_loop) != (1, 1, 3):
        raise RuntimeError(f"unexpected fix shape counts: {(n_guard, n_size, n_loop)}")
    return text


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-dir", type=Path, required=True,
                        help="local Git object store; this script never fetches")
    parser.add_argument("--output", type=Path,
                        default=Path(__file__).with_name("D28_WEBVIEW_CVE_2026_27648_REPLAY.json"))
    args = parser.parse_args()
    tree = git(args.repo_dir, "rev-parse", COMMIT + "^{tree}")
    blob = git(args.repo_dir, "rev-parse", COMMIT + ":" + PATH)
    if (tree, blob) != (TREE, BLOB):
        raise SystemExit("fixed commit/tree/blob mismatch")
    fixed = subprocess.run(["git", "-C", str(args.repo_dir), "show", COMMIT + ":" + PATH], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode("utf-8")
    fixed_sha = hashlib.sha256(fixed.encode()).hexdigest()
    if fixed_sha != FIXED_SHA:
        raise SystemExit("fixed source SHA-256 mismatch")
    reconstructed = reverse_fix(fixed)
    fixed_unit, fixed_run, fixed_findings = scan(fixed, "official_fixed_blob")
    reverse_unit, reverse_run, reverse_findings = scan(reconstructed, "reverse_fix_reconstruction")
    if fixed_findings or len(reverse_findings) != 1:
        raise SystemExit("fixed control or reconstructed positive did not match expectations")
    result = {
        "schema": 1, "repository": REPO, "commit": COMMIT, "tree": tree,
        "path": PATH, "blob": blob, "fixed_source_sha256": fixed_sha,
        "detector": KnownDisclosedCveDetector.detector_id,
        "detector_version": KnownDisclosedCveDetector.version,
        "fixed_control": {"variant": "official_fixed_blob", "parse_status": "not_run",
            "run_status": fixed_run.status, "source_sha256": fixed_unit.sha256,
            "candidate_count": 0},
        "positive_regression": {"variant": "reverse_fix_reconstruction",
            "source_sha256": reverse_unit.sha256, "run_status": reverse_run.status,
            "candidate_count": 1, "candidate": reverse_findings[0]},
        "classification": "candidate-only rule regression; not an upstream vulnerable commit or product confirmation",
        "validated_vulnerability": 0,
        "limitations": [
            "Positive source is reconstructed in memory by reversing the official fix hunk.",
            "Parser is not run, so both executions remain blocked.",
            "No product build, remote input reachability, runtime exploit, or product impact was tested."
        ]
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "tree": tree, "blob": blob,
        "fixed_candidates": 0, "reconstructed_candidates": 1,
        "candidate_line": reverse_findings[0]["line"], "validated_vulnerability": 0},
        ensure_ascii=False))


if __name__ == "__main__":
    main()
