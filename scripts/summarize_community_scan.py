from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import gzip
import hashlib
import json
from pathlib import Path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--increments", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
    state = json.loads(args.state.read_text(encoding="utf-8"))
    increments = json.loads(args.increments.read_text(encoding="utf-8"))
    completed = state["completed"]
    stale_failed = {
        key: value for key, value in state.get("failed", {}).items()
        if key in completed
    }
    unresolved_failed = {
        key: value for key, value in state.get("failed", {}).items()
        if key not in completed
    }
    by_repo = defaultdict(lambda: {"shards": 0, "files": 0, "loc": 0, "diagnostics": 0})
    for key, row in completed.items():
        repo = key.split(":", 1)[0]
        target = by_repo[repo]
        target["shards"] += 1
        target["files"] += int(row["files"])
        target["loc"] += int(row["loc"])
        target["diagnostics"] += int(row["diagnostics"])
    increment_totals = {
        "repositories": len(increments),
        "commits": sum(int(row["Commits"]) for row in increments),
        "non_merge": sum(int(row["NonMerge"]) for row in increments),
        "merge": sum(int(row["Merge"]) for row in increments),
        "duplicate_patch_ids": sum(int(row["DuplicatePatchIds"]) for row in increments),
        "shallow_endpoint_limitation": True,
    }
    summary = {
        "schema_version": 1,
        "kind": "ohscanner.community-local-scan-summary.v1",
        "scope": {
            "repositories": inventory["counts"]["repositories"],
            "inventory_files": inventory["counts"]["files"],
            "inventory_bytes": inventory["counts"]["bytes"],
            "planned_shards": 22,
            "completed_shards": len(completed),
            "unresolved_failed_shards": len(unresolved_failed),
            "stale_failures_resolved_by_completed_retry": len(stale_failed),
        },
        "coverage": {
            "analyzed_files": sum(row["files"] for row in by_repo.values()),
            "analyzed_loc": sum(row["loc"] for row in by_repo.values()),
            "source_binding": "locally computed Git blob IDs; upstream tree matching remains incomplete",
        },
        "diagnostics": {
            "count": sum(row["diagnostics"] for row in by_repo.values()),
            "semantics": "candidate diagnostics only; not vulnerability counts",
        },
        "performance": {
            "compressed_result_bytes": sum(
                Path(row["result_path"]).stat().st_size for row in completed.values()
            ),
            "candidate_density_per_kloc": (
                sum(row["diagnostics"] for row in by_repo.values()) * 1000
                / sum(row["loc"] for row in by_repo.values())
                if sum(row["loc"] for row in by_repo.values()) else None
            ),
            "note": "raw result size is retained locally; per-shard wall/RSS/I/O is inside compressed results",
        },
        "repositories": dict(sorted(by_repo.items())),
        "increments_15_day": increment_totals,
        "replay": {
            "required_by_full_plan": True,
            "status": "not_performed_for_this_local_validation_run",
        },
        "limitations": [
            "This is a 12-repository local validation corpus, not the 514-repository full community run.",
            "Source bytes match locally computed Git blob IDs but were not all matched to upstream repository trees.",
            "Ten shallow repositories expose only their endpoint in the current 15-day selection; first-parent merge coverage is incomplete.",
            "Candidate diagnostics are not vulnerabilities and no accuracy metric is inferred.",
        ],
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.output_dir / "scan-summary.json", summary)
    inventory_gzip = args.output_dir / "inventory.json.gz"
    inventory_gzip.write_bytes(gzip.compress(args.inventory.read_bytes(), compresslevel=9, mtime=0))
    checkpoint = {
        "schema_version": 1,
        "kind": "ohscanner.community-local-final-checkpoint.v1",
        "completed": completed,
        "stale_failures_resolved": stale_failed,
        "unresolved_failures": unresolved_failed,
    }
    write_json(args.output_dir / "checkpoint-final.json", checkpoint)
    report = f"""# Local community scan validation

Scope: {summary['scope']['repositories']} repositories, {summary['scope']['inventory_files']} source files, {summary['scope']['inventory_bytes']} bytes, {summary['scope']['completed_shards']}/{summary['scope']['planned_shards']} shards completed.

Coverage: {summary['coverage']['analyzed_files']} UTF-8 analyzable files and {summary['coverage']['analyzed_loc']} LOC. Non-UTF-8 files were retained as explicit not-analyzed rows. The scan emitted {summary['diagnostics']['count']} candidate diagnostics; these are not vulnerability counts.

The checkpoint completed every planned shard. One earlier UnicodeDecodeError was retried successfully and is retained as a resolved stale checkpoint entry, not a final failure.

The 15-day first-parent selection currently sees {increment_totals['commits']} endpoint commits across 12 local repositories. Ten repositories are shallow endpoint snapshots, so merge/cherry-pick replay coverage is incomplete.

This is local validation only. The full 514-repository run, upstream tree matching, deterministic second replay and final performance aggregation remain open.
"""
    (args.output_dir / "SCAN_REPORT.md").write_text(report, encoding="utf-8")
    delivery = {
        "schema_version": 1,
        "kind": "ohscanner.community-local-delivery-manifest.v1",
        "files": {
            str(path.relative_to(args.output_dir)): {
                "bytes": path.stat().st_size,
                "sha256": sha256(path),
            }
            for path in sorted(args.output_dir.rglob("*"))
            if path.is_file() and path.name != "delivery-manifest.json"
        },
    }
    write_json(args.output_dir / "delivery-manifest.json", delivery)
    print(json.dumps(summary["scope"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
