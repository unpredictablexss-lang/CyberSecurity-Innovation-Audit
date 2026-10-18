"""Manifest-bound D10 replay for pinned DSoftBus sources and HiLog headers.

The upstream Git commit objects are not required to fetch these exact files,
but this is deliberately a research-only direct detector invocation. It does
not claim the public Git Runner accepted a complete repository snapshot.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
from urllib.request import Request, urlopen

from src.ohscanner.contracts import ScanContext, ScanRequest
from src.ohscanner.detectors.data.models import DEFAULT_SOURCE
from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.frontend import index_sources
from src.ohscanner.git_source import GitSource


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "research/data_sensitive/source_manifest.json"
VALIDATION = ROOT / "research/data_sensitive/D9_VALIDATION.json"
OUTPUT = ROOT / "research/data_sensitive/D10_REAL_SOURCE_REPLAY.json"


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def fetch(repository: str, commit: str, path: str) -> bytes:
    url = f"https://raw.githubusercontent.com/{repository}/{commit}/{path}"
    with urlopen(url, timeout=30) as response:
        return response.read()


def fetch_cached(repository: str, commit: str, path: str, cache_dir: Path, *, allow_network: bool = False) -> bytes:
    cached = cache_dir / repository.replace("/", "__") / commit / path
    if cached.is_file():
        return cached.read_bytes()
    if not allow_network:
        raise FileNotFoundError(f"Pinned source cache is missing: {repository}@{commit}:{path}; use the explicit --fetch-upstream option to retrieve it")
    data = fetch(repository, commit, path)
    cached.parent.mkdir(parents=True, exist_ok=True)
    cached.write_bytes(data)
    return data


def github_json(url: str, cache_dir: Path, *, allow_network: bool = False) -> dict:
    cache_file = cache_dir / ".github-api" / (hashlib.sha256(url.encode()).hexdigest() + ".json")
    if cache_file.is_file():
        return json.loads(cache_file.read_text(encoding="utf-8"))
    if not allow_network:
        raise FileNotFoundError(f"Pinned GitHub API cache is missing: {url}; use the explicit --fetch-upstream option to retrieve it")
    request = Request(url, headers={"Accept": "application/vnd.github+json",
                                    "User-Agent": "OHScanner-D10-research-replay"})
    with urlopen(request, timeout=30) as response:
        result = json.load(response)
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text(json.dumps(result), encoding="utf-8")
    return result


def commit_tree(repository: str, commit: str, cache_dir: Path, *, allow_network: bool = False) -> tuple[str, dict[str, dict]]:
    commit_data = github_json(
        f"https://api.github.com/repos/{repository}/git/commits/{commit}", cache_dir, allow_network=allow_network)
    tree_sha = commit_data["tree"]["sha"]
    tree_data = github_json(
        f"https://api.github.com/repos/{repository}/git/trees/{tree_sha}?recursive=1", cache_dir, allow_network=allow_network)
    if tree_data["sha"] != tree_sha or tree_data.get("truncated"):
        raise ValueError(f"incomplete or mismatched upstream tree response for {repository}@{commit}")
    return tree_sha, {entry["path"]: entry for entry in tree_data["tree"]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--cache-dir", type=Path,
                        default=Path("/home/audit/openharmony-targets/pinned-manifest-cache"))
    parser.add_argument("--fetch-upstream", action="store_true",
                        help="explicitly retrieve missing pinned files/API metadata from GitHub")
    args = parser.parse_args()
    rows = json.loads(MANIFEST.read_text(encoding="utf-8"))
    d9 = json.loads(VALIDATION.read_text(encoding="utf-8"))
    args.cache_dir.mkdir(parents=True, exist_ok=True)

    dsoftbus = [row for row in rows if row["repository"] == DEFAULT_SOURCE.repository]
    dsoftbus_tree_sha, dsoftbus_tree = commit_tree(
        DEFAULT_SOURCE.repository, DEFAULT_SOURCE.commit, args.cache_dir,
        allow_network=args.fetch_upstream)
    for row in dsoftbus:
        entry = dsoftbus_tree.get(row["file"])
        if not entry or entry.get("sha") != row["blob"] or entry.get("size") != row["size"]:
            raise ValueError(f"manifest row does not match pinned upstream tree: {row['file']}")
    sources = []
    source_evidence = []
    for row in dsoftbus:
        data = fetch_cached(row["repository"], row["commit"], row["file"], args.cache_dir,
                            allow_network=args.fetch_upstream)
        checks = {
            "size_matches": len(data) == row["size"],
            "sha256_matches": hashlib.sha256(data).hexdigest() == row["sha256"],
            "git_blob_matches": git_blob_sha(data) == row["blob"],
        }
        if not all(checks.values()):
            raise ValueError(f"pinned source verification failed: {row['file']} {checks}")
        cached = args.cache_dir / row["repository"].replace("/", "__") / row["commit"] / row["file"]
        cached.parent.mkdir(parents=True, exist_ok=True)
        cached.write_bytes(data)
        source_evidence.append({"repository": row["repository"], "commit": row["commit"],
                                "path": row["file"], "size": len(data), "git_blob": row["blob"],
                                "sha256": row["sha256"], "checks": checks})
        suffix = Path(row["file"]).suffix.lower()
        if suffix in (".c", ".cpp", ".h"):
            sources.append(GitSource(row["file"], "c" if suffix == ".c" else "cpp",
                                     row["blob"], data))

    sources.sort(key=lambda source: source.path)
    units, ast, parsing = index_sources(tuple(sources))
    request = ScanRequest(
        request_id="d10-manifest-bound-" + DEFAULT_SOURCE.commit[:12],
        repository=DEFAULT_SOURCE.repository,
        commit=DEFAULT_SOURCE.commit,
        snapshot_sha256=snapshot_digest(units),
        target_id="current-component:" + DEFAULT_SOURCE.repository,
        profile_id="d10-manifest-bound-selected-files",
        provenance="fixture",
    )
    run = SensitiveExposureDetector().detect(ScanContext(request, units, {"ast": ast}), units)
    hilog = d9["api_source"]
    hilog_tree_sha = hilog["tree"]
    api_headers = []
    for row in hilog["files"]:
        data = fetch_cached(hilog["repository"], hilog["commit"], row["path"], args.cache_dir,
                            allow_network=args.fetch_upstream)
        checks = {"git_blob_matches": git_blob_sha(data) == row["git_blob"]}
        if not all(checks.values()):
            raise ValueError(f"HiLog API source verification failed: {row['path']} {checks}")
        cached = args.cache_dir / hilog["repository"].replace("/", "__") / hilog["commit"] / row["path"]
        cached.parent.mkdir(parents=True, exist_ok=True)
        cached.write_bytes(data)
        api_headers.append({"repository": hilog["repository"], "commit": hilog["commit"],
                            "path": row["path"], "git_blob": row["git_blob"], "checks": checks,
                            "mapping": row["mapping"]})

    triage_path = "core/authentication/src/auth_session_fsm.c"
    triage_data = fetch_cached(DEFAULT_SOURCE.repository, DEFAULT_SOURCE.commit, triage_path,
                               args.cache_dir, allow_network=args.fetch_upstream)
    triage_entry = dsoftbus_tree.get(triage_path)
    triage_blob = git_blob_sha(triage_data)
    if not triage_entry or triage_entry.get("sha") != triage_blob:
        raise ValueError("cross-file triage context does not match the pinned DSoftBus tree")
    triage_cache = args.cache_dir / DEFAULT_SOURCE.repository.replace("/", "__") / DEFAULT_SOURCE.commit / triage_path
    triage_cache.parent.mkdir(parents=True, exist_ok=True)
    triage_cache.write_bytes(triage_data)

    report = {
        "schema": 1,
        "experiment": "D10 manifest-bound exact-file source replay",
        "source_retrieval": "GitHub raw files pinned by commit; every DSoftBus file checked against manifest size, SHA-256, and Git blob SHA-1",
        "dsoftbus_repository": DEFAULT_SOURCE.repository,
        "dsoftbus_commit": DEFAULT_SOURCE.commit,
        "dsoftbus_upstream_tree_sha": dsoftbus_tree_sha,
        "dsoftbus_manifest_files_verified": len(source_evidence),
        "dsoftbus_code_files_scanned": len(sources),
        "dsoftbus_files": source_evidence,
        "hilog_repository": hilog["repository"],
        "hilog_commit": hilog["commit"],
        "hilog_upstream_tree_sha": hilog_tree_sha,
        "hilog_api_headers_verified": api_headers,
        "candidate_triage_context": {
            "repository": DEFAULT_SOURCE.repository,
            "commit": DEFAULT_SOURCE.commit,
            "path": triage_path,
            "git_blob": triage_blob,
            "sha256": hashlib.sha256(triage_data).hexdigest(),
            "source_review": [
                "OnSessionKeyReturned validates null/length, logs authSeq and key length, then calls AuthSessionSaveSessionKey with key bytes; the reviewed callee forwards the bytes through NewMessagePara into an internal FSM message, with no key argument to a public logging macro at that call site.",
                "EncryptData and DecryptData copy sessionKey.value into a local cipherKey.key and pass it to the corresponding crypto routine; the reviewed call sites log status values, not key bytes.",
                "The local cipherKey.key copies in EncryptData and DecryptData are now modeled as intra-function sensitive-member copies and do not reach a public-log sink in the reviewed functions. Only the AuthSessionSaveSessionKey call remains an unresolved cross-file candidate; this does not establish whole-component absence of exposure.",
            ],
        },
        "detector": asdict(run),
        "source_parsing": parsing,
        "validated_vulnerability": 0,
        "candidate_status": "research_candidate",
        "product_impact": "unknown",
        "limitations": [
            "Local Git commit/tree objects and a complete checkout were unavailable; GitHub API commit/tree metadata and raw files were verified, but this is not public Git Runner replay.",
            "The DSoftBus scope is the frozen selected-file manifest, not whole-component coverage.",
            "HiLog macro definitions are pinned, but their dependency/build binding to the DSoftBus product revision remains unknown.",
            "Static findings are candidates; the two local crypto-copy findings were removed after member-flow modeling because no public-log sink is reached in those functions. One unresolved cross-file call candidate remains; production log enablement, reader access, impact, and runtime validation remain unestablished.",
            "This is not an independent labeled holdout and supports no precision or recall claim.",
            "Zero candidates would not establish absence of sensitive-data exposure.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(args.output), "manifest_files_verified": len(source_evidence),
                      "code_files_scanned": len(sources), "hilog_headers_verified": len(api_headers),
                      "parse_status": parsing["parsing_status"], "status": run.status,
                      "findings": len(run.findings), "validated_vulnerability": 0},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
