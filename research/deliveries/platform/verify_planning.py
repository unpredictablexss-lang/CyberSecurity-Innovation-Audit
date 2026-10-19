"""Reproduce planning on local pinned Git objects; writes only requested output.

Run from repository root: python -m research.deliveries.platform.verify_planning
This is a verification entrypoint, not an API route or scan/validation worker.
"""
import argparse
import json
from pathlib import Path

from src.ohscanner.indexing import prepare_git_context
from src.ohscanner.detectors.catalog import build_registry
from src.workbench.service import detector_metadata
from src.workbench.sources import manifest_from_context
from src.workbench.planning import plan_audit, metadata_from_detectors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-dir", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--include", action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    context, tree, inventory, coverage, sources = prepare_git_context(
        args.repo_dir, args.repository, args.commit, tuple(args.include or ["."]))
    source = manifest_from_context(context, tree, inventory, sources)
    rows = detector_metadata()
    registry = build_registry(tuple(row["id"] for row in rows))
    rows = metadata_from_detectors(rows, registry.detectors())
    first = plan_audit(source, rows)
    second = plan_audit(source, list(reversed(rows)))
    if first != second:
        raise RuntimeError("planning is not deterministic under catalog reordering")
    result = {"verification_kind": "planning_only", "plan": first,
              "existing_core_parse_coverage": coverage,
              "existing_core_inventory": inventory,
              "repeat_and_catalog_reordering_identical": True}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"commit": source.commit, "tree": source.git_tree,
                      "files": len(source.files), "parse": coverage["parsing_status"],
                      "status": first["status"], "suggested_detector_ids": first["suggested_detector_ids"],
                      "plan_sha256": first["plan_sha256"], "execution_status": "not_run",
                      "security_assessment": "unknown", "output": str(args.output)}, indent=2))


if __name__ == "__main__":
    main()
