#!/usr/bin/env python3
"""Aggregate shared_ptr_race candidates over existing pinned component manifests."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence, Tuple


PROJECT_ROOT = Path(__file__).resolve().parents[4]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.ohscanner.detectors.cpp.shared_ptr_race_detector import SharedPtrRaceDetector
from src.ohscanner.git_source import load_git_sources
from src.ohscanner.indexing import prepare_git_context


COMPONENTS = (
    "communication_dsoftbus",
    "distributeddatamgr_kv_store",
    "security_access_token",
    "update_updateservice",
    "window_window_manager",
)


def _resolve_source_root(value: str) -> Path:
    path = Path(value)
    if path.exists():
        return path
    match = re.fullmatch(r"([A-Za-z]):\\(.*)", value)
    if match and os.name != "nt":
        converted = Path("/mnt") / match.group(1).lower() / match.group(2).replace("\\", "/")
        if converted.exists():
            return converted
    return path


def _manifest_paths(manifest: Mapping[str, Any]) -> Tuple[str, ...]:
    paths: List[str] = []
    for shard in manifest.get("shards", []):
        paths.extend(shard.get("paths", []))
    return tuple(sorted(set(paths)))


def _finding_json(finding: Any) -> Dict[str, Any]:
    return {
        "file": finding.file,
        "line": finding.line,
        "column": finding.column,
        "rule_id": finding.rule_id,
        "symbol": finding.symbol,
        "message": finding.message,
        "source_sha256": finding.source_sha256,
        "rule_version": finding.rule_version,
        "candidate_cwe": finding.candidate_cwe,
    }


def _run_component(manifest_path: Path) -> Dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("kind") != "pinned_component_scan_manifest":
        raise ValueError("unsupported manifest kind: " + str(manifest_path))
    source_root = _resolve_source_root(manifest["source_repo_path"])
    if source_root.is_symlink() or not source_root.is_dir():
        raise ValueError("source repo is missing: " + str(source_root))
    repository = manifest["repository"]
    commit = manifest["commit"]
    expected_tree = manifest["git_tree"]
    includes = _manifest_paths(manifest)
    context, tree, inventory, coverage, sources = prepare_git_context(
        source_root, repository, commit, includes
    )
    commit2, tree2, sources2, inventory2 = load_git_sources(source_root, commit, includes)
    if (
        commit2 != context.request.commit
        or tree != tree2
        or tuple((item.path, item.oid, item.data) for item in sources)
        != tuple((item.path, item.oid, item.data) for item in sources2)
        or inventory2 != inventory
        or tree != expected_tree
    ):
        raise ValueError("pinned source identity changed during triage: " + repository)
    run = SharedPtrRaceDetector().detect(context, context.units)
    findings = [_finding_json(item) for item in run.findings]
    counts = Counter((item["file"], item["symbol"]) for item in findings)
    top_members = [
        {"file": file, "symbol": symbol, "count": count}
        for (file, symbol), count in sorted(
            counts.items(), key=lambda item: (-item[1], item[0][0], item[0][1])
        )
    ]
    return {
        "component": manifest["component"],
        "repository": repository,
        "commit": commit,
        "git_tree": tree,
        "snapshot_sha256": context.request.snapshot_sha256,
        "scope_manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "selected_source_files": inventory["selected_source_files"],
        "selected_source_bytes": inventory["selected_source_bytes"],
        "detector": {"id": run.detector_id, "version": run.version, "status": run.status},
        "candidate_count": len(findings),
        "group_count": len(counts),
        "top_members": top_members,
        "findings": findings,
        "coverage": coverage,
        "limitations": list(run.limitations),
    }


def _write_markdown(rows: Sequence[Dict[str, Any]], path: Path) -> None:
    lines = [
        "# shared_ptr_race candidate triage (2026-10-18)",
        "",
        "> Candidate-only lexical triage; counts are access-point diagnostics,",
        "> not vulnerability, root-cause, or Precision/Recall measurements.",
        "",
        "| Component | Files | Candidates | File/symbol groups |",
        "|---|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| `{row['component']}` | {row['selected_source_files']} | "
            f"{row['candidate_count']} | {row['group_count']} |"
        )
    lines.extend(["", "## Top members", ""])
    for row in rows:
        lines.append(f"### `{row['component']}`")
        lines.append("")
        if not row["top_members"]:
            lines.append("- No candidate in the selected lexical scope.")
        for item in row["top_members"][:12]:
            lines.append(f"- `{item['file']}` `{item['symbol']}`: {item['count']} candidate(s)")
        lines.append("")
    lines.extend([
        "## Boundary",
        "",
        "- Source is read from local pinned Git objects; no fetch or checkout.",
        "- Candidates remain `candidate/unassessed`; no product entry or CIA claim.",
        "- This triage does not rewrite the historical 229/208 records.",
    ])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest-dir", type=Path, default=Path("research/evidence/cpp/component_scans"))
    parser.add_argument("--out-dir", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args(argv)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    rows = [
        _run_component(args.manifest_dir / f"{component}.manifest.json")
        for component in COMPONENTS
    ]
    summary = {
        "schema_version": 1,
        "experiment_kind": "a_shared_ptr_race_candidate_triage",
        "status": "completed_with_limitations",
        "detector": "ohscanner.cpp.shared_ptr_race",
        "detector_version": rows[0]["detector"]["version"],
        "components": rows,
        "totals": {
            "components": len(rows),
            "selected_source_files": sum(row["selected_source_files"] for row in rows),
            "selected_source_bytes": sum(row["selected_source_bytes"] for row in rows),
            "candidate_count": sum(row["candidate_count"] for row in rows),
            "group_count": sum(row["group_count"] for row in rows),
            "validated_vulnerability": 0,
            "eligible_for_metrics": False,
        },
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "limitations": [
            "Counts are lexical access-point candidates, not root causes or vulnerabilities.",
            "Pairwise mutex suppression is narrow; cross-function protocols and product builds remain unknown.",
            "No Precision/Recall is computed without an independent reliable labelled holdout.",
        ],
    }
    (args.out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    _write_markdown(rows, args.out_dir / "triage.md")
    print("components=" + str(len(rows)))
    print("candidates=" + str(summary["totals"]["candidate_count"]))
    print("groups=" + str(summary["totals"]["group_count"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
