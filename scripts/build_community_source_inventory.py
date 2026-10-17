from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.ohscanner.community import git_blob_oid, source_language


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest-tag", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    root = ET.parse(args.manifest_tag).getroot()
    if root.tag != "manifest":
        raise ValueError("not an OpenHarmony manifest")
    repositories = []
    for node in root.findall("project"):
        name = node.get("name")
        path = node.get("path")
        revision = node.get("revision")
        if not name or not path or not revision:
            raise ValueError("manifest project missing identity")
        repo_root = args.source_root.joinpath(*path.split("/"))
        if not repo_root.is_dir() or repo_root.is_symlink():
            raise ValueError("source root missing project path: " + path)
        files = []
        for local in sorted(repo_root.rglob("*")):
            if not local.is_file() or local.is_symlink():
                continue
            rel = local.relative_to(repo_root).as_posix()
            if source_language(rel) is None:
                continue
            data = local.read_bytes()
            files.append({
                "path": rel,
                "blob_oid": git_blob_oid(data),
                "source_sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
                "lines": len(data.splitlines()),
                "language": source_language(rel),
            })
        repositories.append({
            "name": name,
            "path": path,
            "commit": revision,
            "source_root": str(repo_root),
            "tree": None,
            "source_binding": "locally_computed_git_blob_identity_not_yet_matched_to_upstream_tree",
            "files": files,
        })
    payload = {
        "schema_version": 1,
        "kind": "ohscanner.openharmony-release-source-inventory.v1",
        "manifest_tag_path": str(args.manifest_tag),
        "manifest_tag_sha256": hashlib.sha256(args.manifest_tag.read_bytes()).hexdigest(),
        "source_root": str(args.source_root),
        "policy": {
            "repository_count_is_dynamic": True,
            "scan_requires_exact_manifest_revision": True,
            "upstream_tree_verification_required_for_complete_source_binding": True,
        },
        "counts": {
            "repositories": len(repositories),
            "files": sum(len(row["files"]) for row in repositories),
            "bytes": sum(file["bytes"] for row in repositories for file in row["files"]),
        },
        "repositories": repositories,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(payload["counts"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
