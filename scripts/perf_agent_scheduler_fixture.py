"""Reproducible offline E4 check for deterministic Agent scheduling helpers.

No model provider is configured or called. Timings describe only these local
Python helpers and are not model latency, quality, or cost measurements.
"""

import json
from pathlib import Path
import sys
from time import perf_counter, process_time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.workbench.agent import (  # noqa: E402
    _rank_source_actions, _remember_tool_result, _tool_result_cache_key,
)
from src.workbench.smart_audit import _root_cause_group_id  # noqa: E402


def main():
    started, cpu_started = perf_counter(), process_time()
    commit = "a" * 40
    report_sha = "b" * 64
    base_candidate = {
        "detector_id": "ohscanner.fixture.detector",
        "detector_version": "1.0.0",
        "rule_id": "FIXTURE-01",
        "file": "src/example.cpp",
        "line": 42,
        "symbol": "handleRequest",
        "source_sha256": "c" * 64,
    }
    same_root = _root_cause_group_id(dict(base_candidate), report_sha)
    duplicate_root = _root_cause_group_id(dict(base_candidate), report_sha)
    distinct_source = _root_cause_group_id(
        {**base_candidate, "source_sha256": "d" * 64}, report_sha
    )
    obligations = [
        {"kind": "attacker_control"},
        {"kind": "guard_dominance"},
        {"kind": "product_build"},
        {"kind": "cross_function_alias"},
    ]
    actions = _rank_source_actions(obligations, [0, 1, 2, 3])

    tool = "read_fixed_source_range"
    args = {"file": "src/example.cpp", "start_line": 38, "line_count": 10}
    key = _tool_result_cache_key(commit, report_sha, "candidate-1", tool, args)
    cache = {}
    first_result = {"file": "src/example.cpp", "source_sha256": "c" * 64,
                    "lines": ["fixed immutable source excerpt"]}
    first_stored = _remember_tool_result(cache, key, first_result)
    second_key = _tool_result_cache_key(commit, report_sha, "candidate-1", tool, args)
    second_result = cache.get(second_key)
    different_commit_key = _tool_result_cache_key("e" * 40, report_sha,
                                                   "candidate-1", tool, args)
    elapsed = perf_counter() - started
    cpu = process_time() - cpu_started
    output = {
        "schema_version": 1,
        "experiment": "E4_offline_scheduler_fixture",
        "status": "completed_offline_fixture_provider_not_run",
        "provider_calls": 0,
        "token_usage": "unknown",
        "provider_cost": "unknown",
        "quality": "not_measured_no_model_or_ground_truth",
        "wall_seconds": elapsed,
        "process_cpu_seconds": cpu,
        "candidate_grouping": {
            "exact_duplicate_same_group": same_root == duplicate_root,
            "changed_source_gets_new_group": same_root != distinct_source,
            "scope": "root-cause identity helper only; full candidate queue not materialized",
        },
        "obligation_scheduling": {
            "requested_indices": [0, 1, 2, 3],
            "ranked_source_action_indices": [row["obligation_index"] for row in actions],
            "unknown_or_non_source_obligations_left_unrouted": [2],
            "selected_tools": [row["tool"] for row in actions],
        },
        "tool_result_memo": {
            "cache_write_succeeded": first_stored,
            "identical_request_reused": second_result == first_result,
            "same_tool_invocations_required": 1,
            "changed_commit_key_differs": key != different_commit_key,
            "operation_scope": "fixture only; production memo remains one authorized operation",
        },
        "budget_policy": "unchanged; no provider authorization or budget was created",
        "interpretation": "Deterministic local scheduling helper check only; not real Agent investigation performance.",
    }
    destination = ROOT / "research/deliveries/performance/full_efficiency_20261021/E4_offline_scheduler.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(output, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
