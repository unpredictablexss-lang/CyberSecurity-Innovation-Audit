# T22: Supervisor race candidate source audit

## Scope and result

This is an independent source audit of A0 rows CR-0001 through CR-0004. It does not change detector code, tests, fixtures, or original A0 statuses, and it does not use another development lane's conclusions as labels.

All four records bind to the same exact source file and same candidate family. Source identity and line mapping are **PASS**. Race existence and impact remain **PARTIAL**: two container-copy accessors have plausible unsynchronized readers and writers, but product thread routing/build conditions and a target-derived runtime reproduction are missing. The two destructor rows currently have weaker race rationale because destructor execution normally follows final shared ownership; the source does not document an independent concurrent caller or manual field use after object destruction. No race is confirmed. No TSan result is claimed.

## Pinned source and original queue

| Property | Verified value |
|---|---|
| Repository/project | `openharmony/resourceschedule_resource_schedule_service` / `foundation/resourceschedule/resource_schedule_service` |
| Commit | `6d60b51a0bc8528c901e42bd80459f9a2030cf9b` |
| Tree | `1c9fde3c8ae5a01325af83a74be06a40f112b4f6` |
| Path | `ressched/plugins/cgroup_sched_plugin/framework/sched_controller/include/supervisor.h` |
| Blob | `270b4cf2916b9df24d3396401c87fb5e9271c5d3` |
| Raw SHA-256 | `8fa6f2fa21dc48e65c2d89b61b8e3de7d4da8c5945a915b9567e6fe0c55947cb` |

The source commit object reports the pinned tree; its tree entry resolves to the pinned blob. The checked-out `supervisor.h` has the same Git blob and SHA-256. The four original queue rows were independently read from the original A0 `queue.csv`: CR-0001..0004 remain `not_testable` and `paused_pending_evidence`. Their source lines are 90, 91, 195 and 236 respectively. The queue was not edited.

The existing A0 345-row verifier also passed from a temporary copy, leaving its source checkout untouched: 345 unique identities, original statuses `9 not_reproduced / 336 not_testable`, queue statuses `9 queued_not_reproduced / 5 queued_first_batch / 331 paused_pending_evidence`, and no source-manifest hash mismatches.

## Source-derived cross-reference

The neighboring source files were checked against blobs in the same pinned commit before reading their call paths: `supervisor.cpp` (`031a58301e777d6dbb29c064fdb3474316d7dcd4`), `cgroup_event_handler.cpp` (`8e8b20d1566b8922e094db9c6e1d92abd2045453`) and `sched_controller.cpp` (`75dfec4440565673ebc7df7a62c602fe7f7b72b8`).

| Candidate | Source expression | Write/read and synchronization evidence | Independent disposition |
|---|---|---|---|
| CR-0001, line 90 | `ProcessRecord::~ProcessRecord()` clears `abilities_` | The destructor clears a vector of `shared_ptr<AbilityInfo>`. No lock/atomic protects it. Normal `shared_ptr` destruction only starts after the final owner releases the record; the audit found no source evidence of concurrent access after that lifetime boundary. The explicit clear also duplicates normal member destruction. | Mapping PASS; race PARTIAL, low follow-up priority. Require evidence of another live access path before building a race harness. |
| CR-0002, line 91 | Same destructor clears `windows_` | Same lifecycle condition as CR-0001; the vector owns `shared_ptr<WindowInfo>`. No lock/atomic exists, but no valid concurrent owner is demonstrated once destruction begins. | Mapping PASS; race PARTIAL, low follow-up priority. |
| CR-0003, line 195 | `Application::GetPidsMap()` returns `pidsMap_` by value | `AddProcessRecord`, `RemoveProcessRecord`, and `GetProcessRecordNonNull` mutate the same map in `supervisor.cpp` without synchronization. Callers include `Supervisor::FindProcessRecordByProcName`, `SearchWindowId`, `CgroupEventHandler::HandleProcessDied`, and synchronous diagnostic paths. Copying the map does not make the copy operation safe against concurrent mutation of the original. | Mapping PASS; unsynchronized overlap is plausible, but whether the exact caller runs concurrently with queued events is unverified. PARTIAL; prioritize source-derived harness investigation. |
| CR-0004, line 236 | `Supervisor::GetUidsMap()` returns `uidsMap_` by value | `GetAppRecordNonNull` inserts and `RemoveApplication` erases from the same map in `supervisor.cpp`, without synchronization. The three `SchedController::DumpProcess*` functions copy it synchronously; resource events are submitted to `CgroupEventHandler`'s FFRT queue. The queue serializes tasks submitted to that queue, but the dump path is not submitted there. | Mapping PASS; concurrent dump/event execution is plausible from these source paths but service routing/scheduling is not established. PARTIAL; highest follow-up priority. |

`SchedController::DispatchResource` posts event handlers to `CgroupEventHandler::PostTask`; `PostTask` submits to one `ffrt::queue`. `SchedController::Dump` directly calls its dump helpers, which read copies and then inspect additional mutable `ProcessRecord` fields. This gives a concrete candidate overlap for CR-0003/4; it does not prove that `OnDump` and callbacks run on distinct threads in the target product build. No relevant `std::mutex`, `ffrt::mutex`, atomic, or lock guard protects `uidsMap_`, `pidsMap_`, `abilities_`, or `windows_` in the inspected operations. The only nearby mutex protects the event handler's delayed-task map, not supervisor state.

## Evidence status and next action

- Four source mappings: **PASS**.
- CR-0001/2 race claim: **PARTIAL**, weak source support; do not spend first on TSan.
- CR-0003/4 race claim: **PARTIAL**, plausible unsynchronized map copy/write overlap; select these first for target-derived harness feasibility.
- Product build profile, exact service-side `OnDump` execution context, concurrent schedule, reproducible target harness, race consequence and CIA impact: **BLOCK** pending component-owner/build evidence.
- TSan: **not run**. Generic TSan controls are not evidence for this target.
- Original A0 `not_testable` / `paused_pending_evidence` states: preserved.

Next evidence request: obtain the exact product build target and compile definitions; trace the service framework's `OnDump` caller thread and plugin callback dispatch; then build a harness that instantiates the real `Supervisor`/`Application` operations and races only source-reachable readers/writers under those conditions. For CR-0001/2, first demonstrate a concurrent access during a valid `ProcessRecord` lifetime. Run TSan only after that source-derived harness is valid, and preserve clean/non-racy and fixed/synchronized controls.

Machine-readable evidence and verifier are adjacent in this directory. A separate task addendum records queue ownership and follow-up priority without changing A0 state.
