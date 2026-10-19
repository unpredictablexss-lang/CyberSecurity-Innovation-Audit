"""Verify D4 source manifests against a complete local Git object database.

Network is disabled by default. --fetch-missing explicitly permits partial-clone
lazy object retrieval, after which all checks are repeated with lazy fetch disabled.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = ROOT / "research/data_sensitive/D4_SOURCE_MANIFEST.json"
DEFAULT_OUTPUT = ROOT / "research/data_sensitive/D13_SOURCE_GIT_OBJECT_VERIFICATION.json"


class VerificationError(RuntimeError):
    pass


def git(repo: Path, *args: str, lazy_fetch: bool = False) -> bytes:
    env = os.environ.copy()
    if lazy_fetch:
        env.pop("GIT_NO_LAZY_FETCH", None)
    else:
        env["GIT_NO_LAZY_FETCH"] = "1"
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        capture_output=True,
        env=env,
        timeout=30,
    )
    if result.returncode:
        detail = result.stderr.decode(errors="replace")[-800:]
        raise VerificationError(f"git {' '.join(args)} failed ({result.returncode}): {detail}")
    return result.stdout


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def fetch_manifest_blobs(repo: Path, manifest: dict) -> int:
    """Download only manifest-pinned raw files and write verified Git blobs locally."""
    fetched = 0
    origin = f"https://raw.githubusercontent.com/{manifest['repository']}"
    commits = {manifest["before_commit"], manifest["after_commit"]}
    for row in manifest["files"]:
        commit = row["commit"]
        if commit not in commits:
            continue
        path = row.get("file", row.get("path"))
        spec = f"{commit}:{path}"
        try:
            git(repo, "cat-file", "-e", spec)
            continue
        except VerificationError:
            pass
        url = f"{origin}/{commit}/{urllib.parse.quote(path, safe='/')}"
        request = urllib.request.Request(url, headers={"User-Agent": "OHScanner-source-verifier/1"})
        with urllib.request.urlopen(request, timeout=30) as response:
            data = response.read()
        if git_blob_sha(data) != row["blob"]:
            raise VerificationError(f"downloaded raw file does not match pinned Git blob: {spec}")
        if hashlib.sha256(data).hexdigest() != row["sha256"] or len(data) != row["size"]:
            raise VerificationError(f"downloaded raw file does not match manifest digest/size: {spec}")
        proc = subprocess.run(
            ["git", "-C", str(repo), "hash-object", "-w", "--stdin"],
            input=data, capture_output=True, check=False, timeout=30,
        )
        if proc.returncode:
            raise VerificationError(f"cannot store verified Git blob for {spec}: {proc.stderr.decode(errors='replace')[-500:]}")
        stored = proc.stdout.decode().strip()
        if stored != row["blob"]:
            raise VerificationError(f"stored object id mismatch for {spec}: {stored}")
        fetched += 1
    return fetched


def commit_info(repo: Path, commit: str) -> dict:
    raw = git(repo, "show", "-s", "--format=%H%x00%T%x00%P%x00%aI%x00%s%x00%b", commit)
    values = raw.decode("utf-8", errors="replace").rstrip("\n").split("\0", 5)
    if len(values) != 6:
        raise VerificationError(f"cannot parse commit metadata for {commit}")
    return {
        "commit": values[0],
        "tree": values[1],
        "parents": values[2].split() if values[2] else [],
        "author_date": values[3],
        "subject": values[4],
        "body": values[5].strip(),
    }


def verify_manifest(repo: Path, manifest: dict) -> dict:
    if git(repo, "rev-parse", "--is-shallow-repository").strip() != b"false":
        raise VerificationError("full commit history is required; shallow repository refused")
    before = manifest["before_commit"]
    after = manifest["after_commit"]
    expected_trees = {
        before: manifest["before_tree"],
        after: manifest["after_tree"],
    }
    commits = {}
    for commit, expected_tree in expected_trees.items():
        if git(repo, "cat-file", "-t", commit).strip() != b"commit":
            raise VerificationError(f"pinned commit object missing: {commit}")
        info = commit_info(repo, commit)
        if info["tree"] != expected_tree:
            raise VerificationError(f"tree mismatch for {commit}: {info['tree']} != {expected_tree}")
        commits[commit] = info

    rows = manifest["files"]
    counts = {before: 0, after: 0}
    file_results = []
    for row in rows:
        commit = row["commit"]
        if commit not in expected_trees:
            continue
        path = row.get("file", row.get("path"))
        if not path:
            raise VerificationError("manifest row has no path")
        if row.get("tree", expected_trees[commit]) != expected_trees[commit]:
            raise VerificationError(f"manifest row tree mismatch: {commit}:{path}")
        spec = f"{commit}:{path}"
        data = git(repo, "cat-file", "blob", spec)
        blob = git_blob_sha(data)
        sha256 = hashlib.sha256(data).hexdigest()
        checks = {
            "git_blob_matches": blob == row["blob"],
            "sha256_matches": sha256 == row["sha256"],
            "size_matches": len(data) == row["size"],
        }
        if not all(checks.values()):
            raise VerificationError(f"source mismatch for {spec}: {checks}")
        counts[commit] += 1
        file_results.append({
            "commit": commit,
            "tree": expected_trees[commit],
            "path": path,
            "blob": blob,
            "sha256": sha256,
            "size": len(data),
            "checks": checks,
        })

    expected_counts = {before: 0, after: 0}
    for row in rows:
        if row["commit"] in expected_counts:
            expected_counts[row["commit"]] += 1
    if any(expected_counts[c] == 0 for c in expected_counts) or counts != expected_counts:
        raise VerificationError(f"manifest-bound file count mismatch: verified={counts}, expected={expected_counts}")
    return {
        "schema": 1,
        "experiment": "D4 manifest verification against local complete Git objects",
        "source_retrieval": "local Git object database; verification subprocesses had GIT_NO_LAZY_FETCH=1",
        "repository": manifest["repository"],
        "is_shallow": False,
        "commits": commits,
        "verified_file_counts": counts,
        "files_verified": len(file_results),
        "files": file_results,
        "historical_change_commit_message": commits[after]["subject"],
        "security_advisory_or_product_fix_claim": False,
        "validated_vulnerability": 0,
        "limitations": [
            "Git tree/blob identity proves exact source object provenance, not that a product built or shipped it.",
            "The later commit message says 'Remove unused sensitive prints'; it is not a security advisory or proof of deployed remediation.",
            "This verifies the D4 source manifest only; it is not a public OHScanner Runner replay or product PoC.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--git-repo", type=Path, required=True, help="complete local Git repository or partial clone")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--fetch-missing", action="store_true",
                        help="explicitly download only manifest-pinned raw files and store verified Git blobs")
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    fetched = fetch_manifest_blobs(args.git_repo, manifest) if args.fetch_missing else 0
    result = verify_manifest(args.git_repo, manifest)
    result["manifest_blobs_downloaded"] = fetched
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": str(args.output),
        "files_verified": result["files_verified"],
        "manifest_blobs_downloaded": fetched,
        "verified_file_counts": result["verified_file_counts"],
        "before_subject": result["commits"][manifest["before_commit"]]["subject"],
        "after_subject": result["commits"][manifest["after_commit"]]["subject"],
        "validated_vulnerability": 0,
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
