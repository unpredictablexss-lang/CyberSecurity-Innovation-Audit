"""Classify pinned refs by the DelayedSingleton singleton.h source identity.

The tool distinguishes exact vulnerable/fixed blob identities from missing or
unknown variants. It does not infer product build applicability or exploitability.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Iterable, List, Mapping, Optional, Sequence, Tuple

from src.ohscanner.git_source import _git


SOURCE_PATH = "base/include/singleton.h"
VULNERABLE_BLOB = "0e0c91010e39558202ab1c7f628c618fd7a09d23"
FIXED_BLOB = "fb65b4d89ff9c60c54bc6a8e106b06935f23f633"


def classify_blob(blob_oid: Optional[str]) -> str:
    if blob_oid is None:
        return "not_present"
    if blob_oid == VULNERABLE_BLOB:
        return "affected"
    if blob_oid == FIXED_BLOB:
        return "fixed"
    return "unknown"


def _ref_blob(repo: Path, ref: str, source_path: str = SOURCE_PATH) -> Optional[str]:
    output = _git(repo, "ls-tree", ref, "--", source_path).decode("utf-8", "replace").strip()
    if not output:
        return None
    parts = output.split()
    if len(parts) < 3 or parts[1] != "blob":
        return None
    return parts[2]


def classify_refs(
    repo: Path,
    refs: Iterable[str],
    *,
    source_path: str = SOURCE_PATH,
) -> List[Dict[str, str]]:
    results = []
    for ref in sorted(set(refs)):
        blob_oid = _ref_blob(repo, ref, source_path)
        results.append(
            {
                "ref": ref,
                "commit": _git(repo, "rev-parse", "--verify", ref + "^{commit}")
                .decode("ascii")
                .strip(),
                "source_path": source_path,
                "blob_oid": blob_oid or "",
                "status": classify_blob(blob_oid),
            }
        )
    return results


def build_version_impact(
    repo: Path,
    refs: Sequence[str],
    *,
    repository: str,
    vulnerable_commit: str,
    fixed_commit: str,
) -> Dict[str, object]:
    records = classify_refs(repo, refs)
    payload = {
        "schema_version": 1,
        "kind": "cpp_shared_ptr_race_version_impact",
        "repository": repository,
        "source_path": SOURCE_PATH,
        "vulnerable_commit": vulnerable_commit,
        "fixed_commit": fixed_commit,
        "vulnerable_blob": VULNERABLE_BLOB,
        "fixed_blob": FIXED_BLOB,
        "records": records,
        "interpretation": (
            "Exact source blob identity only. affected/fixed/not_present/unknown "
            "does not establish product build applicability or exploitability."
        ),
    }
    payload["manifest_sha256"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    return payload


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--vulnerable-commit", required=True)
    parser.add_argument("--fixed-commit", required=True)
    parser.add_argument("--ref", action="append", required=True)
    parser.add_argument("--json-out", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    result = build_version_impact(
        args.repo_root,
        args.ref,
        repository=args.repository,
        vulnerable_commit=args.vulnerable_commit,
        fixed_commit=args.fixed_commit,
    )
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    counts = {}
    for record in result["records"]:
        counts[record["status"]] = counts.get(record["status"], 0) + 1
    print("[OK] version impact:", json.dumps(counts, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
