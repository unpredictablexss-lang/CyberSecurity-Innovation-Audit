#!/usr/bin/env python3
"""Cross-check C7 full-tree closure and independently fetched parent-history evidence."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TREE_REPORT = HERE / "source_tree_closure_20261019.json"
TREE_MANIFEST = HERE / "run_full_snapshot_20261018" / "manifest.json"
HISTORY_REPORT = HERE / "upstream_parent_history_20261019.json"
OUTPUT = HERE / "combined_source_provenance_20261019.json"


def load(path: Path) -> tuple[dict, str]:
    raw = path.read_bytes()
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def main() -> int:
    errors: list[str] = []
    tree, tree_hash = load(TREE_REPORT)
    manifest, manifest_hash = load(TREE_MANIFEST)
    history, history_hash = load(HISTORY_REPORT)

    if tree.get("full_tree_closure_status") != "complete_for_all_selected_commits":
        errors.append("tree closure report is not complete")
    if tree.get("source_manifest_sha256") != manifest_hash:
        errors.append("tree closure report does not bind the current full-snapshot manifest")
    if history.get("result") != "complete_parent_graph_verified_and_targets_are_ancestors_of_current_advertised_heads_or_tags":
        errors.append("upstream parent-history report is not complete")
    post = history.get("post_fetch_history", {})
    if post.get("is_shallow") is not False:
        errors.append("upstream ancestry database remains shallow")

    tree_rows = {row["commit"]: row for row in tree.get("samples", [])}
    manifest_rows = {row["commit"]: row for row in manifest.get("samples", [])}
    history_rows = {row["commit"]: row for row in post.get("per_target", [])}
    expected = set(manifest_rows)
    if len(expected) != 5 or set(tree_rows) != expected or set(history_rows) != expected:
        errors.append("tree, source manifest, and history evidence do not cover the same five commits")

    for commit in sorted(expected & set(tree_rows) & set(history_rows)):
        tr, mr, hr = tree_rows[commit], manifest_rows[commit], history_rows[commit]
        if tr.get("full_tree_closure_status") != "complete" or tr.get("tree_match") is not True:
            errors.append(f"tree closure failed for {commit}")
        if tr.get("tree_expected") != mr.get("tree"):
            errors.append(f"tree report and source manifest disagree for {commit}")
        if hr.get("root_tree_oid") != tr.get("tree_expected"):
            errors.append(f"ancestry root tree and verified source tree disagree for {commit}")
        if hr.get("rev_list_exit") != 0 or hr.get("missing_parent_ids_within_walk"):
            errors.append(f"parent walk is incomplete for {commit}")
        if hr.get("containing_fetched_head_or_tag_ref_count", 0) < 1:
            errors.append(f"no captured advertised head/tag contains {commit}: {commit}")

    result = {
        "schema": "c7-combined-source-provenance.v1",
        "status": "complete_for_five_selected_commits" if not errors else "blocked",
        "tree_closure_report_sha256": tree_hash,
        "source_manifest_sha256": manifest_hash,
        "upstream_parent_history_report_sha256": history_hash,
        "verifier_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "upstream_remote": history.get("remote"),
        "scope": "five selected commits only; does not establish arbitrary unreachable upstream history, product build context, or detector coverage",
        "selected_commit_count": len(expected),
        "tree_closure_and_history_roots_match": not errors,
        "errors": errors,
    }
    OUTPUT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
