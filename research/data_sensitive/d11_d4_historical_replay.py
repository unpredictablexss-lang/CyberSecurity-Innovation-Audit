"""Replay D4 historical profiles from exact manifest-pinned raw GitHub files.

Network is disabled by default. This is a direct research detector invocation,
not a complete Git checkout or public Runner replay.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path
from urllib.request import Request, urlopen

from src.ohscanner.contracts import ScanContext, ScanRequest
from src.ohscanner.detectors.data.historical import HistoricalSensitiveExposureDetector, historical_model
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.frontend import index_sources
from src.ohscanner.git_source import GitSource

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "research/data_sensitive/D4_SOURCE_MANIFEST.json"
PROFILES = ROOT / "src/ohscanner/detectors/data/historical_profiles.json"
OUTPUT = ROOT / "research/data_sensitive/D11_D4_HISTORICAL_REPLAY.json"


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def cached_response(url: str, cache: Path, allow_network: bool) -> bytes:
    if cache.is_file():
        return cache.read_bytes()
    if not allow_network:
        raise FileNotFoundError(f"missing pinned cache: {cache}; pass --fetch-upstream to retrieve")
    request = Request(url, headers={"Accept": "application/vnd.github+json",
                                    "User-Agent": "OHScanner-D11-historical-replay"})
    with urlopen(request, timeout=30) as response:
        data = response.read()
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_bytes(data)
    return data


def verify_source_rows(manifest: dict, commit: str, cache_dir: Path, allow_network: bool):
    rows = [row for row in manifest["files"] if row["commit"] == commit
            and row["file"].lower().endswith((".c", ".cpp", ".h"))]
    if len(rows) != 11:
        raise ValueError(f"expected 11 pinned D4 source files for {commit}, got {len(rows)}")
    expected_tree = next(row["tree"] for row in rows)
    commit_url = f"https://api.github.com/repos/{manifest['repository']}/git/commits/{commit}"
    commit_path = cache_dir / ".api" / f"commit-{commit}.json"
    commit_doc = json.loads(cached_response(commit_url, commit_path, allow_network))
    if commit_doc.get("sha") != commit or commit_doc.get("tree", {}).get("sha") != expected_tree:
        raise ValueError(f"pinned commit/tree mismatch for {commit}")
    tree_url = f"https://api.github.com/repos/{manifest['repository']}/git/trees/{expected_tree}?recursive=1"
    tree_path = cache_dir / ".api" / f"tree-{expected_tree}.json"
    tree_doc = json.loads(cached_response(tree_url, tree_path, allow_network))
    if tree_doc.get("sha") != expected_tree or tree_doc.get("truncated"):
        raise ValueError(f"incomplete or mismatched tree metadata for {commit}")
    tree = {entry["path"]: entry for entry in tree_doc["tree"]}
    sources, evidence = [], []
    for row in rows:
        entry = tree.get(row["file"])
        if not entry or entry.get("type") != "blob" or entry.get("sha") != row["blob"] or entry.get("size") != row["size"]:
            raise ValueError(f"source manifest does not match upstream tree: {row['file']}")
        source_path = cache_dir / commit / row["file"]
        data = cached_response(
            f"https://raw.githubusercontent.com/{manifest['repository']}/{commit}/{row['file']}",
            source_path, allow_network)
        checks = {
            "size_matches": len(data) == row["size"],
            "sha256_matches": hashlib.sha256(data).hexdigest() == row["sha256"],
            "git_blob_matches": git_blob_sha(data) == row["blob"],
        }
        if not all(checks.values()):
            raise ValueError(f"source byte verification failed for {row['file']}: {checks}")
        language = "c" if row["file"].lower().endswith(".c") else "cpp"
        sources.append(GitSource(row["file"], language, row["blob"], data))
        evidence.append({"path": row["file"], "blob": row["blob"], "sha256": row["sha256"],
                         "size": len(data), "checks": checks})
    return sources, evidence, expected_tree, len(tree)


def replay(commit: str, manifest: dict, cache_dir: Path, allow_network: bool) -> dict:
    started = time.monotonic()
    model = historical_model(commit)
    sources, evidence, tree, tree_entries = verify_source_rows(
        manifest, commit, cache_dir, allow_network)
    sources.sort(key=lambda item: item.path)
    units, ast, parsing = index_sources(tuple(sources))
    request = ScanRequest(
        request_id="d11-historical-" + commit[:12], repository=manifest["repository"],
        commit=commit, snapshot_sha256=snapshot_digest(units),
        target_id="current-component:" + manifest["repository"],
        profile_id="d11-manifest-bound-historical-" + model.profile["profile_id"],
        provenance="fixture",
    )
    run = HistoricalSensitiveExposureDetector(model).detect(
        ScanContext(request, units, {"ast": ast}), units)
    return {
        "commit": commit, "tree": tree, "tree_entries": tree_entries,
        "source_files_verified": len(evidence), "source_files": evidence,
        "parse_summary": parsing, "detector_status": run.status,
        "candidate_count": len(run.findings),
        "candidates": [{
            "file": finding.file, "line": finding.line, "symbol": finding.symbol,
            "rule_id": finding.rule_id, "candidate_cwe": finding.candidate_cwe,
            "source_sha256": finding.source_sha256, "message": finding.message,
            "evidence_obligations": [
                {"kind": item.kind, "description": item.description, "status": item.status}
                for item in finding.evidence_obligations
            ],
        } for finding in run.findings],
        "limitations": list(run.limitations),
        "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path,
                        default=Path("/tmp/ohscanner-d11-d4-source-cache"))
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--fetch-upstream", action="store_true",
                        help="download missing pinned API metadata and source files")
    args = parser.parse_args()
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    profiles = json.loads(PROFILES.read_text(encoding="utf-8"))["profiles"]
    commits = (manifest["before_commit"], manifest["after_commit"])
    if [p["commit"] for p in profiles] != list(commits):
        raise ValueError("historical profile commit order does not match D4 manifest")
    args.cache_dir.mkdir(parents=True, exist_ok=True)
    runs = [replay(commit, manifest, args.cache_dir, args.fetch_upstream) for commit in commits]
    result = {
        "schema": 1,
        "experiment": "D11 D4 manifest-bound historical source replay",
        "source_retrieval": "GitHub API commit/tree and raw pinned files, each checked against the frozen manifest",
        "repository": manifest["repository"],
        "detector_version": HistoricalSensitiveExposureDetector.version,
        "runs": runs,
        "candidate_delta": runs[0]["candidate_count"] - runs[1]["candidate_count"],
        "interpretation": "Research candidate delta only; both profiles are partial/blocked and do not prove a vulnerability or fix.",
        "public_runner_invoked": False,
        "runtime_harness": "not_run; Docker is unavailable in this WSL environment",
        "validated_vulnerability": 0,
        "product_impact": "unknown",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": str(args.output),
        "runs": [{"commit": row["commit"], "verified": row["source_files_verified"],
                  "parse": row["parse_summary"]["parsing_status"],
                  "status": row["detector_status"], "candidates": row["candidate_count"]}
                 for row in runs],
        "candidate_delta": result["candidate_delta"],
        "validated_vulnerability": 0,
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
