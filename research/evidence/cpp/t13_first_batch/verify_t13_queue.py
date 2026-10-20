#!/usr/bin/env python3
"""Verify the T13 first-batch evidence against the frozen 345-row A0 queue."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
MIRRORS = ROOT.parents[1] / "openharmony" / ".repo" / "project-objects"
QUEUE_REL = Path("research/deliveries/cpp/a0_triage_20261019/queue.json")
T12_REL = Path("research/evidence/cpp/t12_a_line_wave_acceptance_20261020.json")
BASE = "8e79a238c3689ec6ffc2d98559a801e1620042ed"
EXPECTED_IDS = {"CR-0016", "CR-0017", "CR-0018", "CR-0336", "CR-0342"}


def git(*args: str, cwd: Path = ROOT) -> bytes:
    return subprocess.check_output(["git", *args], cwd=cwd)


def git_mirror(repo: str, *args: str) -> bytes:
    mirror = MIRRORS / f"{repo}.git"
    return subprocess.check_output(["git", "--git-dir", str(mirror), *args])


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def queue_pairs(payload: dict) -> dict[str, tuple[str, str]]:
    return {
        row["queue_id"]: (
            row["original_status"],
            row["queue_status"],
        )
        for row in payload["queue"]
    }


def verify_source(identity: dict, repo: str, commit: str, tree: str) -> dict:
    actual_tree = git_mirror(repo, "show", "-s", "--format=%T", commit).decode().strip()
    assert actual_tree == tree, f"{repo} {commit}: tree mismatch {actual_tree} != {tree}"
    path = identity["path"]
    entry = git_mirror(repo, "ls-tree", commit, "--", path).decode().strip()
    fields = entry.split()
    assert len(fields) >= 4 and fields[2] == identity["blob"], (
        f"{repo}:{path}: blob mismatch: {entry}"
    )
    raw = git_mirror(repo, "cat-file", "blob", identity["blob"])
    actual_sha = hashlib.sha256(raw).hexdigest()
    assert actual_sha == identity["sha256"], f"{repo}:{path}: SHA-256 mismatch"
    assert len(raw) == identity["bytes"], f"{repo}:{path}: byte-count mismatch"
    return {
        "repository": repo,
        "commit": commit,
        "tree": actual_tree,
        "path": path,
        "blob": fields[2],
        "bytes": len(raw),
        "sha256": actual_sha,
        "verified": True,
    }


def main() -> int:
    current = load_json(ROOT / QUEUE_REL)
    frozen_bytes = git("show", f"{BASE}:{QUEUE_REL.as_posix()}")
    frozen = json.loads(frozen_bytes)
    current_pairs = queue_pairs(current)
    frozen_pairs = queue_pairs(frozen)
    assert len(current_pairs) == 345 and len(set(current_pairs)) == 345
    assert current_pairs == frozen_pairs, "the full A0 ID/original-status/queue-status table changed"
    first_batch = {qid for qid, (_, status) in current_pairs.items() if status == "queued_first_batch"}
    assert first_batch == EXPECTED_IDS, f"first-batch membership changed: {sorted(first_batch)}"

    t12 = load_json(ROOT / T12_REL)["queue_345"]
    assert t12["overall_ok"] and t12["ids_and_statuses_preserved"]
    assert t12["unique_queue_ids"] == 345
    assert t12["original_status_counts"] == {"not_reproduced": 9, "not_testable": 336}
    assert t12["queue_status_counts"] == {
        "queued_not_reproduced": 9,
        "queued_first_batch": 5,
        "paused_pending_evidence": 331,
    }

    mirror_checks = []
    for qid in sorted(EXPECTED_IDS):
        record = load_json(HERE / f"{qid}.json")
        qrow = next(row for row in current["queue"] if row["queue_id"] == qid)
        assert record["queue_id"] == qid
        assert record["candidate_id"] == qrow["candidate_id"]
        assert record["original_status"] == qrow["original_status"] == "not_testable"
        assert record["queue_status"] == qrow["queue_status"] == "queued_first_batch"
        source = record["source"]
        assert source["repository"] == qrow["repository"]
        for field in ("commit", "tree", "path", "blob", "sha256"):
            assert source[field] == qrow.get("source_sha256" if field == "sha256" else field), (
                f"{qid}: {field} differs from frozen queue"
            )
        checks = [verify_source(source, source["repository"].split("/", 1)[1], source["commit"], source["tree"])]
        related = record.get("related_source")
        if related:
            checks.append(verify_source(related, source["repository"].split("/", 1)[1], source["commit"], source["tree"]))
        mirror_checks.extend({"queue_id": qid, **check} for check in checks)

    external = subprocess.check_output(
        ["python", str(ROOT / "research/deliveries/cpp/a0_triage_20261019/verify_triage.py")],
        cwd=ROOT,
    )
    reconciliation = json.loads(external.decode("utf-8-sig"))
    assert reconciliation["overall_ok"]
    assert reconciliation["source_candidates"] == reconciliation["queue_rows"] == 345

    result = {
        "schema_version": 1,
        "audit": "T13 independent A0 first-batch queue and source verifier",
        "base_commit": BASE,
        "full_queue_ids": len(current_pairs),
        "full_queue_pairs_identical_to_base": True,
        "first_batch_ids": sorted(EXPECTED_IDS),
        "selected_rows_remain_not_testable_queued": True,
        "T12_queue_verifier": t12,
        "original_A0_verifier": {
            "overall_ok": reconciliation["overall_ok"],
            "source_hash_manifest_entries": reconciliation["source_hash_manifest_entries"],
            "source_hash_manifest_bytes": reconciliation["source_hash_manifest_bytes"],
            "queue_rows": reconciliation["queue_rows"],
            "unique_queue_ids": reconciliation["unique_queue_ids"],
            "original_status_counts": reconciliation["original_status_counts"],
            "queue_status_counts": reconciliation["queue_status_counts"],
        },
        "source_objects": mirror_checks,
        "overall_ok": True,
    }
    out = HERE / "t13_queue_verification_20261020.json"
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
