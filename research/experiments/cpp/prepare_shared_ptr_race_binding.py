"""Prepare a local Git binding manifest for shared_ptr_race native evidence.

The output binds repository identity, exact commits, Git tree/blob IDs and raw
source SHA-256 values. It is a draft input manifest: the separately recorded
SHA-256 must be pinned by an independent evidence workflow before it is treated
as trusted ground truth.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from research.experiments.cpp.shared_ptr_race_native_evidence import (
    binding_manifest_sha256,
    load_pinned_unit,
)


def build_binding_manifest(
    repo_root: Path,
    repository: str,
    source_path: str,
    vulnerable_commit: str,
    fixed_commit: str,
) -> dict:
    revisions = {}
    for revision, commit in (
        ("vulnerable", vulnerable_commit),
        ("fixed", fixed_commit),
    ):
        pinned = load_pinned_unit(repo_root, repository, commit, source_path)
        revisions[revision] = {
            "commit": commit,
            "git_tree": pinned.git_tree,
            "blob_oid": pinned.blob_oid,
            "source_sha256": pinned.unit.sha256,
        }
    return {
        "schema_version": 1,
        "repository": repository,
        "source_path": source_path,
        "revisions": revisions,
    }


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--source-path", required=True)
    parser.add_argument("--vulnerable-commit", required=True)
    parser.add_argument("--fixed-commit", required=True)
    parser.add_argument("--json-out", required=True, type=Path)
    parser.add_argument("--sha256-out", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    manifest = build_binding_manifest(
        args.repo_root,
        args.repository,
        args.source_path,
        args.vulnerable_commit,
        args.fixed_commit,
    )
    manifest_text = json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
    digest = binding_manifest_sha256(manifest)
    if args.json_out.resolve() == args.sha256_out.resolve():
        raise ValueError("manifest and hash output paths must differ")
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.sha256_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(manifest_text, encoding="utf-8")
    args.sha256_out.write_text(digest + "\n", encoding="utf-8")
    print(f"[OK] wrote draft binding manifest {args.json_out} with SHA-256 {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
