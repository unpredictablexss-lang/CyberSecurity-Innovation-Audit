"""Run the bounded JS/TS/ArkTS security detector on pinned OpenHarmony manifests."""

from __future__ import annotations

import argparse
import hashlib
import json
import resource
import sys
import time
from pathlib import Path
from typing import Any, Dict, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.ohscanner.detectors.script_security_detector import ScriptSecurityDetector
from src.ohscanner.indexing import environment_fingerprint, prepare_git_context


COMPONENTS = (
    "communication_dsoftbus",
    "distributeddatamgr_kv_store",
    "security_access_token",
    "update_updateservice",
    "window_window_manager",
)


def paths(manifest):
    return tuple(sorted({path for shard in manifest.get("shards", []) for path in shard.get("paths", [])}))


def finding_dict(item):
    return {
        "file": item.file,
        "line": item.line,
        "column": item.column,
        "rule_id": item.rule_id,
        "candidate_cwe": item.candidate_cwe,
        "symbol": item.symbol,
        "message": item.message,
        "source_sha256": item.source_sha256,
        "obligations": [obligation.__dict__ for obligation in item.evidence_obligations],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for component in COMPONENTS:
        manifest_path = args.manifest_dir / f"{component}.manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        source_root = Path(manifest["source_repo_path"])
        if not source_root.exists() and manifest["source_repo_path"][:2].lower() in {"e:", "c:", "d:"}:
            source_root = Path("/mnt") / manifest["source_repo_path"][0].lower() / manifest["source_repo_path"][3:].replace("\\", "/")
        started = time.perf_counter()
        context, tree, inventory, coverage, _sources = prepare_git_context(
            source_root, manifest["repository"], manifest["commit"], paths(manifest)
        )
        run = ScriptSecurityDetector().detect(context, context.units)
        report = {
            "schema_version": 1,
            "experiment_kind": "script_security_pinned_component_scan",
            "status": run.status,
            "component": component,
            "repository": manifest["repository"],
            "commit": manifest["commit"],
            "git_tree": tree,
            "snapshot_sha256": context.request.snapshot_sha256,
            "coverage": coverage,
            "candidate_count": len(run.findings),
            "findings": [finding_dict(item) for item in run.findings],
            "limitations": list(run.limitations),
            "wall_seconds": time.perf_counter() - started,
        }
        (args.out_dir / f"{component}.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + chr(10), encoding="utf-8")
        rows.append({key: report[key] for key in ("component", "repository", "commit", "candidate_count", "wall_seconds", "status")})
    summary = {
        "schema_version": 1,
        "experiment_kind": "script_security_pinned_summary",
        "status": "completed_with_limitations",
        "components": rows,
        "totals": {
            "candidate_count": sum(row["candidate_count"] for row in rows),
            "wall_seconds": sum(row["wall_seconds"] for row in rows),
            "process_peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        },
        "environment": environment_fingerprint(),
        "limitations": [
            "Lexical JS/TS/ArkTS rules only; no mature ArkTS semantics or product permission proof.",
            "Candidates are not vulnerabilities and zero findings is not a safe verdict.",
        ],
    }
    (args.out_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + chr(10), encoding="utf-8")
    lines = ["# Script security pinned summary", "", "| Component | Status | Candidates | Wall s |", "|---|---|---:|---:|"]
    for row in rows:
        lines.append(f"| `{row['component']}` | {row['status']} | {row['candidate_count']} | {row['wall_seconds']:.3f} |")
    lines.extend(["", "Lexical candidates only; not product vulnerabilities.", ""])
    (args.out_dir / "summary.md").write_text(chr(10).join(lines), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
