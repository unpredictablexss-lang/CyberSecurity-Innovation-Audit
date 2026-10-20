# T23 — Supervisor shared_ptr race independent acceptance

## Verdict

| Scope | Result | Evidence |
|---|---|---|
| Existing `shared_ptr_race` detector mechanism | **PASS** | 39 focused unit tests pass; both exact CLI scopes independently reproduce D23's rule version, source binding, coverage and finding counts. This validates the existing mechanism controls, not container-element race detection. |
| A0 CR-0001..0004 case | **PARTIAL** | Exact source and four queue rows bind; the two complete selected units produce no candidates. No evidence proves cross-thread access to the same `shared_ptr` object. The three-file scope has a parser-partial callsite file, and no product-bound harness or race confirmation exists. |

The zero-finding runs are **not** a safety result and do not establish detector recall for the reported container operations. CR-0001..0004 remain `not_testable / paused_pending_evidence`.

## Independent source and queue check

Using the pinned OpenHarmony project object database, T23 verified:

- repository: `openharmony/resourceschedule_resource_schedule_service`
- commit: `6d60b51a0bc8528c901e42bd80459f9a2030cf9b`
- tree: `1c9fde3c8ae5a01325af83a74be06a40f112b4f6`
- `supervisor.h` blob: `270b4cf2916b9df24d3396401c87fb5e9271c5d3`
- raw source SHA-256: `8fa6f2fa21dc48e65c2d89b61b8e3de7d4da8c5945a915b9567e6fe0c55947cb`

The commit tree resolves the path to the declared blob, and the blob bytes hash to the declared SHA-256. Queue rows CR-0001..0004 independently match the same repository/commit/tree/path/blob/hash and lines 90, 91, 195, 236. Their candidate IDs, `not_testable` original states and `paused_pending_evidence` queue states are unchanged. The source lines identify, respectively, `abilities_.clear()`, `windows_.clear()`, `return pidsMap_`, and `return uidsMap_`.

## Replays

Both commands ran from the clean T23 scanner checkout and read the exact pinned source commit from a temporary clone made from the external project object database. Output JSON is retained with this report.

1. Header-only baseline:

   `python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\worktrees\a-t23-supervisor-race-acceptance-20261020\tmp\d23-resource-service-replay --repository openharmony/resourceschedule_resource_schedule_service --commit 6d60b51a0bc8528c901e42bd80459f9a2030cf9b --include ressched/plugins/cgroup_sched_plugin/framework/sched_controller/include/supervisor.h --detector ohscanner.cpp.shared_ptr_race --json-out research/evidence/cpp/t23_supervisor_race_header_replay_20261020.json`

   **T23 result:** `completed`, 1 file / 7,794 bytes, parser complete, detector `ohscanner.cpp.shared_ptr_race` v0.5.1 completed, 0 diagnostics. Detector coverage binds the header source SHA-256 to the pinned blob.

2. Bounded declaration/implementation fragment:

   `python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\worktrees\a-t23-supervisor-race-acceptance-20261020\tmp\d23-resource-service-replay --repository openharmony/resourceschedule_resource_schedule_service --commit 6d60b51a0bc8528c901e42bd80459f9a2030cf9b --include ressched/plugins/cgroup_sched_plugin/framework/sched_controller/include/supervisor.h --include ressched/plugins/cgroup_sched_plugin/framework/sched_controller/supervisor.cpp --include ressched/plugins/cgroup_sched_plugin/framework/sched_controller/cgroup_event_handler.cpp --detector ohscanner.cpp.shared_ptr_race --json-out research/evidence/cpp/t23_supervisor_race_fragment_replay_20261020.json`

   **T23 result:** `completed_with_limitations`, 3 files / 79,535 bytes. `supervisor.h` and `supervisor.cpp` are complete and analyzed (627 LOC total); `cgroup_event_handler.cpp` is partial with parser errors at lines 72, 612 and 639 and was not analyzed. Detector v0.5.1 completed with 0 diagnostics. One selected applicable file remains unanalyzed.

The T23 replay summaries exactly match the D23 JSON outcomes. The partial callsite file prevents a full-scope conclusion; the complete header/implementation results are descriptive syntax-level evidence only. This replay neither proves safety nor establishes that the detector can catch the A0 allegation.

## Test and scope gates

- `python -m unittest tests.detectors.test_cpp_shared_ptr_race_detector -v`: **39 passed, 0 failed**.
- A0 verifier, run from a temporary copy to avoid rewriting its tracked outputs: **overall_ok=true**, 345 source candidates / 345 rows / 345 unique IDs; original status counts remain 9 `not_reproduced`, 336 `not_testable`; no source hash mismatch. Compact output is recorded in [the A0 verifier summary](t23_a0_queue_verification_20261020.json).
- `python research/evidence/cpp/verify_t23_supervisor_race_acceptance.py`: verifies pinned Git objects, four queue rows, CLI source hashes, D23/T23 replay parity, partial boundary and A0 verifier result.
- `python scripts/check_change_scope.py --base 8ec5f56a12e90bba56953b39eb17faa20e154da9 --lane cpp`: **0 violations** after temporary clone cleanup.
- `git diff --check`: **clean** after final report/task-tree edits.

## Remaining evidence

The static evidence does not establish a cross-thread race on the same shared-pointer object. CR-0001/0002 need a source-derived concurrent access during a valid `ProcessRecord` lifetime; CR-0003/0004 need the actual service-thread schedule for map readers/writers. All four still need product build/policy context, a target-derived concurrent harness, and reproducible consequence evidence before a race verdict. Preserve the queue states until that evidence is available.
