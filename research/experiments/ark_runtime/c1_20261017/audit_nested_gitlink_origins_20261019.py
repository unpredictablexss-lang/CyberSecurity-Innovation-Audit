#!/usr/bin/env python3
"""Map exact snapshot gitlinks to parent .gitmodules origins without fetching or mutating sources."""
from __future__ import annotations

import configparser
import json
import hashlib
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parents[3]
ARCHIVE_ROOT = Path("/home/deepsleep/c-line-c1-profile-20261018/openharmony-git-archive-20261019")
REPORT = ARCHIVE_ROOT / "materialization_manifest.json"
OUTPUT = HERE / "nested_gitlink_origins_20261019.json"


def main() -> int:
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    rows = []
    for parent in report["projects"]:
        if not parent.get("gitlinks"):
            continue
        parent_root = ARCHIVE_ROOT / parent["path"]
        modules_file = parent_root / ".gitmodules"
        cfg = configparser.ConfigParser(interpolation=None)
        if modules_file.is_file():
            cfg.read(modules_file, encoding="utf-8")
        modules = {cfg[s].get("path"): cfg[s].get("url") for s in cfg.sections() if cfg[s].get("path")}
        for link in parent["gitlinks"]:
            path = link["path"]
            entries = sum(1 for _ in (parent_root / path).iterdir()) if (parent_root / path).is_dir() else None
            rows.append({
                "parent_project": parent["path"],
                "gitlink_path": path,
                "gitlink_commit": link["commit"],
                "gitmodules_path_match": path in modules,
                "declared_url": modules.get(path),
                "archive_directory_entry_count": entries,
                "commit_content_materialized": entries is not None and entries > 0,
            })
    output = {
        "schema": "ohscanner.c1.nested-gitlink-origins/v1",
        "materialization_report_sha256": hashlib.sha256(REPORT.read_bytes()).hexdigest(),
        "project_count": len(report["projects"]),
        "gitlink_count": len(rows),
        "gitlinks_with_declared_origin": sum(row["gitmodules_path_match"] for row in rows),
        "gitlinks_without_declared_origin": sum(not row["gitmodules_path_match"] for row in rows),
        "gitlink_content_materialized_count": sum(row["commit_content_materialized"] for row in rows),
        "gitlinks": rows,
        "scope": "read-only mapping from each parent project .gitmodules; no remote fetch and no source mutation",
    }
    OUTPUT.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: output[key] for key in ["schema", "project_count", "gitlink_count", "gitlinks_with_declared_origin", "gitlinks_without_declared_origin", "gitlink_content_materialized_count"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
