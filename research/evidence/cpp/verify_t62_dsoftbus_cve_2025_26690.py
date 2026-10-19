#!/usr/bin/env python3
"""Verify T62's independent CVE-2025-26690 source and replay evidence."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
REL = Path("research/evidence/cpp")
SOURCE_PATH = "core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp"
OBJECTS = {
    "vulnerable": {
        "commit": "258662cd9840b55a31546a72d91027f6368cea84",
        "tree": "366a4ced9400653c9628c0b677e4ae657c0e7bd8",
        "blob": "a82b71fb5520b02278a4af695bbe918d14c1048e",
        "sha256": "5453bd68645a7708f0d9ef9c214451a4735a256b5223729f6808ab34095125a6",
        "bytes": 8502,
        "report": REL / "a_static_baseline_20261019/t62-cve-2025-26690-vulnerable.json",
        "lines": [71, 82, 97, 108, 123],
    },
    "fixed": {
        "commit": "192f3e11d74beeaa3d879333471deb8a24a7e1c5",
        "tree": "1d58ba0ef706a6f69dd372bd496c8058810882aa",
        "blob": "13ddbe93a7f617784dec0f3761e09f66b5c3217c",
        "sha256": "5a093d91efc624147d40bf3f4dbbe3ab7ab6d724b17978298e9d5c30d9e5eb81",
        "bytes": 9387,
        "report": REL / "a_static_baseline_20261019/t62-cve-2025-26690-fixed.json",
        "lines": [],
    },
}


def git(git_dir: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "--git-dir", str(git_dir), *args])


def verify(git_dir: Path) -> dict:
    identities = {}
    for name, expected in OBJECTS.items():
        commit = expected["commit"]
        commit_record = git(git_dir, "show", "-s", "--format=%H %T %P", commit).decode().strip().split()
        assert commit_record[0] == commit and commit_record[1] == expected["tree"], (name, commit_record)
        entry = git(git_dir, "ls-tree", commit, SOURCE_PATH).decode().split()
        assert entry[1] == "blob" and entry[2] == expected["blob"], (name, entry)
        data = git(git_dir, "cat-file", "blob", expected["blob"])
        assert len(data) == expected["bytes"]
        assert hashlib.sha256(data).hexdigest() == expected["sha256"]

        report = json.loads((ROOT / expected["report"]).read_text(encoding="utf-8"))
        assert report["commit"] == commit and report["git_tree"] == expected["tree"]
        assert report["source_parsing"]["parsing_status"] == {"complete": 1}
        runs = [r for r in report["detector_runs"] if r["tool"] == "ohscanner.cpp.null_dereference"]
        assert len(runs) == 1 and runs[0]["status"] == "blocked"
        assert runs[0]["diagnostic_count"] == len(expected["lines"])
        cov = report["detector_coverage"]["detectors"]["ohscanner.cpp.null_dereference"]
        assert cov["status"] == "partial" and cov["coverage_counts"] == {
            "complete": 0, "partial": 1, "not_analyzed": 0, "failed": 0
        }
        lines = sorted(d["line"] for d in runs[0]["diagnostics"])
        assert lines == expected["lines"], (name, lines)
        identities[name] = {
            "commit": commit,
            "tree": expected["tree"],
            "blob": expected["blob"],
            "byte_length": len(data),
            "sha256": expected["sha256"],
            "parse": "complete",
            "detector_coverage": "partial",
            "execution": "blocked",
            "candidate_lines": lines,
        }

    assert git(git_dir, "show", "-s", "--format=%P", OBJECTS["fixed"]["commit"]).decode().strip().split()[0] == OBJECTS["vulnerable"]["commit"]

    queue_path = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv"
    queue_bytes = queue_path.read_bytes()
    base_bytes = subprocess.check_output(["git", "show", f"HEAD:{queue_path.relative_to(ROOT).as_posix()}"], cwd=ROOT)
    assert queue_bytes == base_bytes, "A0 queue changed relative to HEAD"
    rows = list(csv.DictReader(queue_path.open(encoding="utf-8-sig", newline="")))
    assert len(rows) == len({r["candidate_id"] for r in rows}) == 345
    assert {s: sum(r["original_status"] == s for r in rows) for s in ("not_testable", "not_reproduced")} == {
        "not_testable": 336,
        "not_reproduced": 9,
    }
    assert {s: sum(r["queue_status"] == s for r in rows) for s in (
        "paused_pending_evidence", "queued_first_batch", "queued_not_reproduced"
    )} == {"paused_pending_evidence": 331, "queued_first_batch": 5, "queued_not_reproduced": 9}
    assert not any("dsoftbus" in r["repository"] or "client_proxy.cpp" in r["path"] for r in rows)

    overlay = json.loads((ROOT / "research/evidence/cpp/a_case_status_updates_20261020.json").read_text(encoding="utf-8"))
    case = next(x for x in overlay["updates"] if x["case_id"] == "openharmony-cve-2025-26690")
    assert case["baseline_status_at_2026_10_19"] == "BLOCK" and case["current_status"] == "PARTIAL"

    return {
        "schema_version": 1,
        "task": "T62 independent acceptance",
        "case": "CVE-2025-26690",
        "source_objects": identities,
        "a0": {
            "row_count": len(rows),
            "unique_candidate_ids": len({r["candidate_id"] for r in rows}),
            "original_status_counts": {"not_testable": 336, "not_reproduced": 9},
            "queue_status_counts": {"paused_pending_evidence": 331, "queued_first_batch": 5, "queued_not_reproduced": 9},
            "source_row_present": False,
            "queue_bytes_unchanged_from_head": True,
        },
        "prior_case_matrix": {"baseline": "BLOCK", "current": "PARTIAL"},
        "controls": {
            "focused_detector_tests": {"command": "python -m unittest tests.detectors.test_cpp_null_dereference_detector tests.detectors.test_cpp_null_dereference_signal_controls -q", "passed": 21},
            "upstream_fixed_pair": "available; five checks before corresponding dereferences",
            "dsoftbus_safe_unrelated_source_controls": "missing",
            "mechanism_fixture_controls": "covered by focused detector tests; not case-specific source controls",
        },
        "provenance": {
            "fetch_head_remote": "https://gitcode.com/openharmony/communication_dsoftbus",
            "local_commit_tree_blob_graph_verified": True,
            "signed_publisher_attestation": "not verified",
            "synthetic_single_file_package_only": False,
        },
        "disposition": "PARTIAL/BLOCK",
        "limitations": [
            "Detector semantics remain partial/blocked (0/1 complete) on both sources despite complete syntax parsing.",
            "No product build, compile flags/macros, target-derived allocation-failure test, caller reachability, or CIA impact evidence.",
            "No independently bound dSoftBus-specific safe/unrelated source controls.",
            "Fixed zero-result is not a safety conclusion.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--git-dir", type=Path, default=Path(r"D:\openHarmonyScanner\tmp\d22-upstream-dsoftbus-object-store"))
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    result = verify(args.git_dir)
    encoded = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.json_out:
        args.json_out.write_text(encoded, encoding="utf-8")
    print(encoded, end="")


if __name__ == "__main__":
    main()
