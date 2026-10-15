"""Classify pinned refs of one repository by the source identity of one file.

The unit of evidence is the *exact blob* at a ref: not a version range, not a
guess from commit dates, not a similarity score. A ref whose blob at
`--source-path` equals the vulnerable blob is `affected`; one whose blob equals
the fixed blob is `fixed`; a ref that does not carry the file at all is
`not_present`; anything else is `unknown`. `unknown` is never folded into
`fixed`, and when no fixed boundary is supplied the `fixed` state is
unreachable by construction.

This generalizes the shared_ptr-race version-impact script: the file, the two
boundary commits and the record `kind` come from the command line instead of
module constants, and the source path is threaded all the way into the
classifier -- without that, refs would be classified against the wrong file.

Scope: blob identity plus commit ancestry. It does not establish product build
applicability, device exposure or exploitability, and a ref carrying neither
boundary blob is not thereby safe.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from src.ohscanner.git_source import _git  # noqa: E402

STATUSES = ("affected", "fixed", "not_present", "unknown")

INTERPRETATION = (
    "Exact source blob identity at a named ref, plus the ancestry of the two "
    "boundary commits. affected/fixed/not_present/unknown describes the file's "
    "identity on that ref only: it does not establish product build "
    "applicability, whether a device shipped the ref, or exploitability. A ref "
    "that carries neither boundary blob is not thereby safe."
)


def classify_blob(
    blob_oid: Optional[str],
    *,
    vulnerable_blob: str,
    fixed_blob: str,
) -> str:
    """Four-state classification of one blob. Empty fixed_blob never yields `fixed`."""
    if blob_oid is None:
        return "not_present"
    if blob_oid == vulnerable_blob:
        return "affected"
    if fixed_blob and blob_oid == fixed_blob:
        return "fixed"
    return "unknown"


def _try_git(repo: Path, *args: str) -> Optional[str]:
    """Return stripped stdout, or None when the object/ref is not there.

    A missing ref and an unreadable object are both non-answers; callers record
    them as `unknown`/`not_present` rather than inventing a verdict.
    """
    try:
        return _git(repo, *args).decode("utf-8", "replace").strip()
    except (ValueError, OSError):
        return None


def _blob_at(repo: Path, commit: str, source_path: str) -> Optional[str]:
    if not commit:
        return None
    return _try_git(repo, "rev-parse", "--verify", commit + ":" + source_path) or None


def _ref_blob(repo: Path, ref: str, source_path: str) -> Optional[str]:
    output = _try_git(repo, "ls-tree", ref, "--", source_path)
    if not output:
        return None
    parts = output.split()
    if len(parts) < 3 or parts[1] != "blob":
        return None
    return parts[2]


def _blob_sha256(repo: Path, oid: str, cache: Dict[str, str]) -> str:
    """Content digest of a blob, so a record can be cross-referenced by content.

    Best effort, offline only. `_git` forbids lazy fetching, so in a partial
    (blob:none) clone a blob that was never materialized simply cannot be hashed
    here; the record then carries the oid with an empty digest rather than a
    digest obtained over the network. Cached by blob oid: a tag and the branch
    that points at it share one blob, and hashing it per ref would repeat
    identical work tens of times.
    """
    if oid in cache:
        return cache[oid]
    try:
        data = _git(repo, "cat-file", "blob", oid)
        digest = hashlib.sha256(data).hexdigest()
    except (ValueError, OSError):
        digest = ""
    cache[oid] = digest
    return digest


def _is_ancestor(repo: Path, ancestor: str, descendant: str) -> bool:
    """True only when git exits 0. Both SHAs are pre-resolved, so exit 1 means no."""
    try:
        _git(repo, "merge-base", "--is-ancestor", ancestor, descendant)
        return True
    except (ValueError, OSError):
        return False


def list_refs(
    repo: Path,
    *,
    tags: bool = False,
    branches: bool = False,
    globs: Sequence[str] = (),
    explicit: Sequence[str] = (),
) -> List[str]:
    """The ref set to classify, as full refnames. Filters apply to the short name."""
    names: List[str] = list(explicit)
    if tags:
        names.extend((_try_git(repo, "for-each-ref", "--format=%(refname)", "refs/tags") or "")
                     .splitlines())
    if branches:
        names.extend((_try_git(repo, "for-each-ref", "--format=%(refname)",
                               "refs/remotes/origin") or "").splitlines())
    selected = []
    for name in names:
        name = name.strip()
        if not name or name.endswith("/HEAD"):
            continue
        short = name
        for prefix in ("refs/tags/", "refs/remotes/origin/", "refs/heads/"):
            if short.startswith(prefix):
                short = short[len(prefix):]
                break
        if globs and not any(fnmatch.fnmatch(short, pattern) for pattern in globs):
            continue
        selected.append(name)
    return sorted(set(selected))


def classify_refs(
    repo: Path,
    refs: Iterable[str],
    *,
    source_path: str,
    vulnerable_blob: str,
    fixed_blob: str,
    vulnerable_commit: str = "",
    fixed_commit: str = "",
) -> List[Dict[str, object]]:
    """One record per ref. Passing `source_path` down is the point of the signature."""
    cache: Dict[str, str] = {}
    records: List[Dict[str, object]] = []
    for ref in sorted(set(refs)):
        commit = _try_git(repo, "rev-parse", "--verify", ref + "^{commit}") or ""
        blob_oid = _ref_blob(repo, ref, source_path) if commit else None
        # A ref that does not resolve is unknown, not `not_present`: claiming the
        # file is absent there would assert something about a revision that was
        # never read.
        if not commit:
            status, note = "unknown", "the ref did not resolve to a commit"
        elif blob_oid is None:
            status, note = "not_present", "the file is absent at this ref"
        else:
            status, note = classify_blob(blob_oid, vulnerable_blob=vulnerable_blob,
                                         fixed_blob=fixed_blob), ""
        record: Dict[str, object] = {
            "ref": ref,
            "commit": commit,
            "source_path": source_path,
            "blob_oid": blob_oid or "",
            "blob_sha256": _blob_sha256(repo, blob_oid, cache) if blob_oid else "",
            "status": status,
            "note": note,
        }
        if commit and vulnerable_commit:
            record["vulnerable_commit_reachable"] = _is_ancestor(repo, vulnerable_commit, commit)
        if commit and fixed_commit:
            record["fixed_commit_reachable"] = _is_ancestor(repo, fixed_commit, commit)
        records.append(record)
    return records


def build_version_impact(
    repo: Path,
    refs: Sequence[str],
    *,
    repository: str,
    kind: str,
    source_path: str,
    vulnerable_commit: str,
    fixed_commit: str = "",
) -> Dict[str, object]:
    vulnerable_blob = _blob_at(repo, vulnerable_commit, source_path)
    if not vulnerable_blob:
        raise ValueError(
            "the source file is not present at the vulnerable commit; "
            "the boundary cannot be stated instead of being guessed: "
            + vulnerable_commit + ":" + source_path)
    fixed_blob = _blob_at(repo, fixed_commit, source_path) if fixed_commit else ""
    if fixed_commit and not fixed_blob:
        raise ValueError(
            "the source file is not present at the fixed commit, so the fixed "
            "boundary cannot be stated: " + fixed_commit + ":" + source_path)

    records = classify_refs(
        repo, refs, source_path=source_path,
        vulnerable_blob=vulnerable_blob, fixed_blob=fixed_blob or "",
        vulnerable_commit=vulnerable_commit, fixed_commit=fixed_commit)

    counts: Dict[str, int] = {status: 0 for status in STATUSES}
    for record in records:
        counts[record["status"]] = counts.get(record["status"], 0) + 1
    digest_available = sum(1 for record in records if record["blob_sha256"])

    payload: Dict[str, object] = {
        "schema_version": 1,
        "kind": kind,
        "repository": repository,
        "source_path": source_path,
        "vulnerable_commit": vulnerable_commit,
        "fixed_commit": fixed_commit,
        "vulnerable_blob": vulnerable_blob,
        "fixed_blob": fixed_blob or "",
        "vulnerable_blob_sha256": _blob_sha256(repo, vulnerable_blob, {}),
        "fixed_blob_sha256": _blob_sha256(repo, fixed_blob, {}) if fixed_blob else "",
        "ref_count": len(records),
        "counts": counts,
        "content_digest_coverage": {
            "blobs_at_refs": len(records),
            "digests_available": digest_available,
            "digests_unavailable": len(records) - digest_available,
        },
        "records": records,
        "interpretation": INTERPRETATION,
        "known_limitations": [
            "Blob identity is not build applicability: a ref may carry the "
            "vulnerable file while never building the component that calls it.",
            "`unknown` is a non-answer, not a fix. A ref that carries neither "
            "boundary blob may hold a further variant of the file, and this "
            "record does not read that content.",
            "The ref set is the one that was scanned; absence of a ref is not "
            "absence of the code.",
            "Commit ancestry is used only to split refs that carry the fixed "
            "blob from refs that do not; it is not a statement about releases.",
            "Content digests are read from the local object store only. In a "
            "partial (blob:none) clone a blob that was never materialized "
            "cannot be hashed offline, so its digest is omitted and only the "
            "blob oid identifies it; no fetch is performed to fill the gap.",
        ],
    }
    payload["manifest_sha256"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        .encode("utf-8")).hexdigest()
    return payload


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--kind", required=True, help="record kind, e.g. ipc_auth01_version_impact")
    parser.add_argument("--source-path", required=True)
    parser.add_argument("--vulnerable-commit", required=True)
    parser.add_argument("--fixed-commit", default="",
                        help="omit when no upstream fix exists; `fixed` is then unreachable")
    parser.add_argument("--ref", action="append", default=[], help="explicit refname")
    parser.add_argument("--tags", action="store_true", help="scan every tag")
    parser.add_argument("--branches", action="store_true", help="scan every origin branch")
    parser.add_argument("--ref-glob", action="append", default=[],
                        help="keep only refs whose short name matches; repeatable")
    parser.add_argument("--json-out", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    if not (args.tags or args.branches or args.ref):
        raise SystemExit("select a ref set: --tags, --branches and/or --ref")
    refs = list_refs(args.repo_root, tags=args.tags, branches=args.branches,
                     globs=args.ref_glob, explicit=args.ref)
    if not refs:
        raise SystemExit("the ref selection matched nothing; refusing to write an empty scan")
    result = build_version_impact(
        args.repo_root, refs, repository=args.repository, kind=args.kind,
        source_path=args.source_path, vulnerable_commit=args.vulnerable_commit,
        fixed_commit=args.fixed_commit)
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n",
                             encoding="utf-8")
    print("[OK] version impact over", result["ref_count"], "refs:",
          json.dumps(result["counts"], sort_keys=True))
    print("[OK] manifest_sha256:", result["manifest_sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
