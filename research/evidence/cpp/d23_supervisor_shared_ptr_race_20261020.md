# D23 — Supervisor shared_ptr race candidate quality

## Result

No detector or fixture change is justified by the available evidence. The current `ohscanner.cpp.shared_ptr_race` rule (detector version `0.5.1`, rule ID `ohcpp-shared-ptr-race-candidate-001`) reports no candidate for the pinned header, and the four A0 locations do not themselves demonstrate unsynchronized access to the same `std::shared_ptr` object across threads. They identify operations on containers that hold shared pointers. Container concurrency is a separate access pattern, and widening this detector based on the line locations alone would risk conflating container races with shared-pointer-object races.

This is a source-binding and rule-scope assessment, not a safe verdict. The case remains unresolved for concurrency and product reachability.

## Pinned source identity

- Repository: `openharmony/resourceschedule_resource_schedule_service`
- Commit: `6d60b51a0bc8528c901e42bd80459f9a2030cf9b`
- Tree: `1c9fde3c8ae5a01325af83a74be06a40f112b4f6`
- Path: `ressched/plugins/cgroup_sched_plugin/framework/sched_controller/include/supervisor.h`
- Blob: `270b4cf2916b9df24d3396401c87fb5e9271c5d3`
- SHA-256: `8fa6f2fa21dc48e65c2d89b61b8e3de7d4da8c5945a915b9567e6fe0c55947cb`

The working source file SHA-256 matched the declared value. The CLI replay independently reported the pinned commit and tree, and the same source SHA in detector coverage.

## Candidate-location review

| Line | Source operation | What the syntax establishes | What remains unproven |
|---:|---|---|---|
| 90 | `abilities_.clear()` in `ProcessRecord::~ProcessRecord()` | Container destruction/clear of `vector<shared_ptr<AbilityInfo>>` | Whether a live thread accesses this vector or one of its shared-pointer elements concurrently; object lifetime and destruction serialization |
| 91 | `windows_.clear()` in `ProcessRecord::~ProcessRecord()` | Container destruction/clear of `vector<shared_ptr<WindowInfo>>` | Same thread-overlap and lifetime questions |
| 195 | `return pidsMap_` in `Application::GetPidsMap() const` | Copies a `map<pid_t, shared_ptr<ProcessRecord>>` | Whether another thread mutates the same map during copy; callsite thread and lock/strand protocol |
| 236 | `return uidsMap_` in `Supervisor::GetUidsMap() const` | Copies a `map<int32_t, shared_ptr<Application>>` | Whether another thread mutates the same map during copy; callsite thread and lock/strand protocol |

The declarations are containers (`vector`/`map`) with `shared_ptr` elements, not direct `shared_ptr<T>` data members. The detector's documented scope recognizes direct class/static `shared_ptr` members and lexical reads/writes attributable to those members. It does not model container element identity or concurrent container operations. No `mutex`, atomic shared-pointer access, strand, or equivalent protocol is declared in this header around these four operations; absence in this header does not prove the class is used concurrently.

The pinned implementation also contains container operations such as vector lookup/push/erase and map lookup/insert/erase in `supervisor.cpp`. That indicates read/write shapes to the containers, but source text alone does not establish that two such operations can overlap across threads. The selected `cgroup_event_handler.cpp` contains one partial parse, so its callsite and threading evidence cannot close that gap.

## Current CLI replay

The scanner was run against a normal-path source clone checked out at the exact pinned commit. This avoided the local `.repo` worktree's Windows Git reparse-point failure. Both raw JSON outputs are stored beside this report.

1. Header-only baseline:

   `python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\d23-resource-service-clone --repository openharmony/resourceschedule_resource_schedule_service --commit 6d60b51a0bc8528c901e42bd80459f9a2030cf9b --include ressched/plugins/cgroup_sched_plugin/framework/sched_controller/include/supervisor.h --detector ohscanner.cpp.shared_ptr_race --json-out research/evidence/cpp/d23_supervisor_race_header_baseline_20261020.json`

   Outcome: run `completed`; 1 selected C++ file, 249 LOC, parser `complete`, detector `0.5.1` `completed`, 0 findings, about `0.013 s`. Source coverage SHA-256 matches the pinned identity. This is not a safety conclusion.

2. Bounded declaration/implementation fragment:

   `python -m src.cli ohscan-run --repo-dir D:\openHarmonyScanner\tmp\d23-resource-service-clone --repository openharmony/resourceschedule_resource_schedule_service --commit 6d60b51a0bc8528c901e42bd80459f9a2030cf9b --include ressched/plugins/cgroup_sched_plugin/framework/sched_controller/include/supervisor.h --include ressched/plugins/cgroup_sched_plugin/framework/sched_controller/supervisor.cpp --include ressched/plugins/cgroup_sched_plugin/framework/sched_controller/cgroup_event_handler.cpp --detector ohscanner.cpp.shared_ptr_race --json-out research/evidence/cpp/d23_supervisor_race_fragment_20261020.json`

   Outcome: run `completed_with_limitations`; 3 selected files / 79,535 bytes; parser statuses: 2 `complete`, 1 `partial`; the partial file is `cgroup_event_handler.cpp` with a syntax error at line 72. Detector status is `completed`, 0 findings, about `0.025 s`; it analyzed the two complete files (627 LOC). One applicable file was not analyzed. The zero result cannot be interpreted as safe or as evidence that the rule catches the reported pattern.

Parser dependencies were available under the Windows project Python. The WSL project environment lacked `tree_sitter_c`; the successful CLI runs therefore used the Windows Python environment and did not change parser versions.

## Rule controls and verification

- Focused unit suite: `python -m unittest tests.detectors.test_cpp_shared_ptr_race_detector -v` — passed (the existing suite covers direct shared_ptr positive, fixed atomic, safe/unrelated, renamed, lock, and incomplete/partial shapes).
- `python scripts/check_change_scope.py --base 8ec5f56a12e90bba56953b39eb17faa20e154da9 --lane cpp` — run after placing evidence artifacts under `research/evidence/cpp`; see final recorded output in handoff.
- `git diff --check` — clean.
- No Catalog, API, shared parser, A0 status, or detector code was changed.

The existing controls do not validate nested `container<shared_ptr<T>>` element access or establish cross-thread access overlap for this component. Do not treat their passing status as acceptance of CR-0001..0004.

## Remaining evidence needed

To decide whether these are genuine race candidates and justify a generalized rule extension, bind the relevant implementation and callers to this exact tree, recover the complete `cgroup_event_handler.cpp` parse context, establish which event/callback threads invoke the container reads/writes/destructor, and inspect the effective synchronization and ownership/lifetime protocol across those callers. If these checks show a specific missed same-object unsynchronized pattern, add generalized nested-container controls (positive, fixed/atomic or lock-protected, safe, unrelated, renamed, and partial) before changing the rule. Until then, preserve the current behavior and leave the A0 queue status untouched.
