#!/usr/bin/env python3
"""Verify T57 exact bindings, IPC replays, and unchanged 345-row A0 queue."""
from __future__ import annotations
import argparse, hashlib, json, subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
AUDIT = ROOT / "research/evidence/cpp/t57_safwk_test_stubs_audit_20261029.json"
QUEUE = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.json"
IDS = [f"CR-{n:04d}" for n in range(247, 252)]
COMMIT = "21c83c874a34e8d28e6a355a3b56e5167252ed27"


def git(repo: str, *args: str) -> bytes:
    return subprocess.check_output(["git", f"--git-dir={repo}", *args], stderr=subprocess.PIPE)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--git-dir", required=True, help="systemabilitymgr_safwk project Git object database")
    args = ap.parse_args()
    audit = json.loads(AUDIT.read_text(encoding="utf-8"))
    queue = json.loads(QUEUE.read_text(encoding="utf-8"))["queue"]
    errors = []
    if len(queue) != 345 or len({r["queue_id"] for r in queue}) != 345:
        errors.append("A0 must retain 345 unique rows")
    counts = {s: sum(r.get("original_status") == s for r in queue) for s in ("not_reproduced", "not_testable")}
    if counts != {"not_reproduced": 9, "not_testable": 336}:
        errors.append(f"A0 original status counts changed: {counts}")
    rows = {r["queue_id"]: r for r in queue}
    src = audit["source"]
    if src["commit"] != COMMIT or git(args.git_dir, "rev-parse", f"{COMMIT}^{{tree}}").decode().strip() != src["tree"]:
        errors.append("pinned source commit/tree mismatch")
    for key, obj in src["objects"].items():
        try:
            raw = git(args.git_dir, "show", f"{COMMIT}:{obj['path']}")
            oid = git(args.git_dir, "rev-parse", f"{COMMIT}:{obj['path']}").decode().strip()
            if oid != obj["blob"] or len(raw) != obj["bytes"] or hashlib.sha256(raw).hexdigest() != obj["sha256"]:
                errors.append(f"object binding mismatch: {key}")
        except subprocess.CalledProcessError:
            errors.append(f"missing source object: {key}")
    cli_reports = {}
    for name in ("listen", "probe"):
        p = ROOT / f"research/evidence/cpp/t57_safwk_{name}_cli_20261029.json"
        raw = json.loads(p.read_text(encoding="utf-8")); cli_reports[name] = raw
        expected = src["objects"][name]
        cov = raw["detector_coverage"]["detectors"]["ohscanner.interface.ipc"]
        run = raw["detector_runs"][0]
        if raw["commit"] != COMMIT or raw["git_tree"] != src["tree"]:
            errors.append(f"{name}: CLI source pin mismatch")
        if raw["scope"]["declared_scope"] != [expected["path"]] or raw["scope"]["selected_source_files"] != 1:
            errors.append(f"{name}: scope mismatch")
        if raw["source_parsing"]["parsing_status"] != {"complete": 1} or cov["coverage_counts"].get("complete") != 1:
            errors.append(f"{name}: parse/coverage incomplete")
        if run["tool"] != "ohscanner.interface.ipc" or run["tool_version"] != "0.12.12" or run["status"] != "completed" or run["diagnostic_count"] != 0:
            errors.append(f"{name}: current CLI mismatch")
        if cov["source_sha256"].get(expected["path"]) != expected["sha256"]:
            errors.append(f"{name}: CLI source hash mismatch")
    for case in audit["cases"]:
        row = rows.get(case["queue_id"])
        if not row or any(str(row[k]) != str(case[k]) for k in ("candidate_id", "repository", "commit", "tree", "path", "line", "blob", "source_sha256", "a0_rule", "original_status", "queue_status") if k != "a0_rule"):
            errors.append(f"{case['queue_id']}: frozen A0 binding mismatch")
        elif row.get("rule") != case["a0_rule"]:
            errors.append(f"{case['queue_id']}: A0 rule changed")
        if case["original_status"] != "not_testable" or case["queue_status"] != "paused_pending_evidence" or case["current_findings_at_line"] != 0:
            errors.append(f"{case['queue_id']}: expected state/findings changed")
    if set(c["queue_id"] for c in audit["cases"]) != set(IDS) or audit["disposition"] != "PARTIAL/BLOCK":
        errors.append("case set or disposition mismatch")
    result = {"overall_ok": not errors, "audit": "T57 Safwk test Stubs CR-0247–CR-0251", "a0_rows": len(queue), "selected_ids": IDS, "original_status_counts": counts, "queue_states_unchanged": not errors, "errors": errors}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
