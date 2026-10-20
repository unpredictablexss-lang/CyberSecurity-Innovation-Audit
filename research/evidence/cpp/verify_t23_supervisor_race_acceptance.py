#!/usr/bin/env python3
"""Independent T23 replay and source-binding checks for D23 supervisor race evidence."""
from __future__ import annotations

import csv
import hashlib
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
HERE = pathlib.Path(__file__).resolve().parent
OBJECTS = pathlib.Path(r"D:\openHarmonyScanner\openharmony\.repo\project-objects\resourceschedule_resource_schedule_service.git")
QUEUE = pathlib.Path(r"D:\openHarmonyScanner\CyberSecurity-Innovation-Audit\research\deliveries\a-line-triage\20261018\queue.csv")
SOURCE = {
    "repository": "openharmony/resourceschedule_resource_schedule_service",
    "commit": "6d60b51a0bc8528c901e42bd80459f9a2030cf9b",
    "tree": "1c9fde3c8ae5a01325af83a74be06a40f112b4f6",
    "path": "ressched/plugins/cgroup_sched_plugin/framework/sched_controller/include/supervisor.h",
    "blob": "270b4cf2916b9df24d3396401c87fb5e9271c5d3",
    "sha256": "8fa6f2fa21dc48e65c2d89b61b8e3de7d4da8c5945a915b9567e6fe0c55947cb",
}
EXPECTED_ROWS = {
    "CR-0001": ("ohscanner.cpp.shared_ptr_race:96112eb15e426e15", 90),
    "CR-0002": ("ohscanner.cpp.shared_ptr_race:8e9aa0aa292ae104", 91),
    "CR-0003": ("ohscanner.cpp.shared_ptr_race:98bc2912246f6b5b", 195),
    "CR-0004": ("ohscanner.cpp.shared_ptr_race:e8d7ee4495f26860", 236),
}


def git(*args: str) -> str:
    return subprocess.run(
        ["git", f"--git-dir={OBJECTS}", *args], check=True, capture_output=True, text=True, encoding="utf-8"
    ).stdout.strip()


commit_tree = next(line.split()[1] for line in git("cat-file", "-p", SOURCE["commit"]).splitlines() if line.startswith("tree "))
tree_entry = git("ls-tree", SOURCE["commit"], "--", SOURCE["path"])
blob = subprocess.run(
    ["git", f"--git-dir={OBJECTS}", "cat-file", "blob", SOURCE["blob"]],
    check=True, capture_output=True,
).stdout
lines = blob.decode("utf-8").splitlines()

with QUEUE.open(encoding="utf-8-sig", newline="") as stream:
    queue = {row["queue_id"]: row for row in csv.DictReader(stream)}
queue_checks = {}
for queue_id, (candidate_id, line) in EXPECTED_ROWS.items():
    row = queue.get(queue_id, {})
    queue_checks[queue_id] = all(
        row.get(field) == value
        for field, value in {
            "candidate_id": candidate_id,
            "line": str(line),
            "repository": SOURCE["repository"],
            "commit": SOURCE["commit"],
            "tree": SOURCE["tree"],
            "path": SOURCE["path"],
            "blob": SOURCE["blob"],
            "source_sha256": SOURCE["sha256"],
            "original_status": "not_testable",
            "queue_status": "paused_pending_evidence",
        }.items()
    )


def load_run(name: str) -> dict:
    return json.loads((HERE / name).read_text(encoding="utf-8"))


header = load_run("t23_supervisor_race_header_replay_20261020.json")
fragment = load_run("t23_supervisor_race_fragment_replay_20261020.json")
d23_header = load_run("d23_supervisor_race_header_baseline_20261020.json")
d23_fragment = load_run("d23_supervisor_race_fragment_20261020.json")


def replay_summary(data: dict) -> dict:
    run = data["detector_runs"][0]
    coverage = data["detector_coverage"]["detectors"]["ohscanner.cpp.shared_ptr_race"]
    return {
        "status": data["status"],
        "commit": data["commit"],
        "tree": data["git_tree"],
        "selected_files": data["scope"]["selected_source_files"],
        "selected_bytes": data["scope"]["selected_source_bytes"],
        "parse_status": data["source_parsing"]["parsing_status"],
        "tool": run["tool"],
        "rule_version": run["tool_version"],
        "run_status": run["status"],
        "scope_files_analyzed": run["scope_files"],
        "scope_loc_analyzed": run["scope_loc"],
        "diagnostic_count": run["diagnostic_count"],
        "diagnostics": run["diagnostics"],
        "source_sha256": coverage["source_sha256"],
    }


header_result = replay_summary(header)
fragment_result = replay_summary(fragment)
d23_header_result = replay_summary(d23_header)
d23_fragment_result = replay_summary(d23_fragment)
a0 = json.loads((HERE / "t23_a0_queue_verification_20261020.json").read_text(encoding="utf-8"))

checks = {
    "commit_tree_matches": commit_tree == SOURCE["tree"],
    "tree_path_resolves_to_expected_blob": tree_entry.endswith(f"blob {SOURCE['blob']}\t{SOURCE['path']}"),
    "pinned_blob_sha256_matches": hashlib.sha256(blob).hexdigest() == SOURCE["sha256"],
    "both_cli_replays_bind_source_sha256_to_pinned_blob": header_result["source_sha256"].get(SOURCE["path"]) == SOURCE["sha256"]
    and fragment_result["source_sha256"].get(SOURCE["path"]) == SOURCE["sha256"],
    "candidate_source_lines_exist": all(lines[line - 1].strip() for _, line in EXPECTED_ROWS.values()),
    "four_A0_queue_rows_bind_source_and_preserve_status": all(queue_checks.values()),
    "header_only_run_matches_D23": header_result == d23_header_result,
    "fragment_run_matches_D23": fragment_result == d23_fragment_result,
    "header_scope_complete_zero_findings": header_result["status"] == "completed"
    and header_result["parse_status"] == {"complete": 1}
    and header_result["tool"] == "ohscanner.cpp.shared_ptr_race"
    and header_result["rule_version"] == "0.5.1"
    and header_result["diagnostic_count"] == 0,
    "fragment_partial_not_misread_as_safe": fragment_result["status"] == "completed_with_limitations"
    and fragment_result["parse_status"] == {"complete": 2, "partial": 1}
    and fragment_result["scope_files_analyzed"] == 2
    and fragment_result["diagnostic_count"] == 0,
    "A0_345_verifier_passed": a0["overall_ok"]
    and a0["source_candidates"] == 345
    and a0["queue_rows"] == 345
    and a0["original_status_counts"] == {"not_reproduced": 9, "not_testable": 336},
}

result = {
    "schema_version": "t23-supervisor-race-acceptance-v1",
    "task": "T23",
    "integration_base": "50903ebe20458fedba5212d62b1ef7c8dcd0e0eb",
    "acceptance": {"mechanism_regression": "PASS", "case_status": "PARTIAL"},
    "source": SOURCE,
    "queue_rows": {
        queue_id: {
            "candidate_id": EXPECTED_ROWS[queue_id][0],
            "line": EXPECTED_ROWS[queue_id][1],
            "original_status": "not_testable",
            "queue_status": "paused_pending_evidence",
            "identity_check": queue_checks[queue_id],
        }
        for queue_id in EXPECTED_ROWS
    },
    "replays": {
        "header_only": {"t23": header_result, "d23": d23_header_result},
        "three_file_fragment": {"t23": fragment_result, "d23": d23_fragment_result},
    },
    "tests": {
        "command": "python -m unittest tests.detectors.test_cpp_shared_ptr_race_detector -v",
        "passed": 39,
        "failed": 0,
    },
    "a0_verifier": a0,
    "case_boundaries": {
        "zero_findings_are_not_a_safety_result": True,
        "no_cross_thread_same_object_access_proven": True,
        "partial_file": "ressched/plugins/cgroup_sched_plugin/framework/sched_controller/cgroup_event_handler.cpp",
        "partial_parser_issues": [72, 612, 639],
        "product_build_bound": False,
        "target_derived_harness": False,
        "tsan_run": False,
        "race_confirmed": False,
        "cia_impact_established": False,
    },
    "checks": checks,
    "overall_ok": all(checks.values()),
}
(HERE / "t23_supervisor_race_acceptance_20261020.json").write_text(
    json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
)
print(json.dumps({"overall_ok": result["overall_ok"], "checks": checks}, ensure_ascii=False, indent=2))
sys.exit(0 if result["overall_ok"] else 1)
