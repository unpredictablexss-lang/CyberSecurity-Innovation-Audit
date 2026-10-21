# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/window_window_manager`
- Pinned commit: `8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`
- Git tree: `24e60146ba2fe4af3aaef20b306a1e306df44617`
- Snapshot SHA-256: `cc28d8ab5d852fc156d0b2a1926d0ae6c89b39f6eef0dabc5c7922adf9f482a4`
- Source files indexed: 117
- Parsing coverage: `{"complete": 61, "partial": 56}`
- Detector runs: 2
- Total unverified diagnostics: 0
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.lifetime` | blocked | 61 | 60 | 1 | 56 | 0 | partial |
| `ohscanner.cpp.shared_ptr_race` | completed | 61 | 61 | 0 | 56 | 0 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| — | — | — | — | No reported candidate; NOT proof of safety |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.lifetime`: partial, 60/117 applicable files examined; unexamined=57
- `ohscanner.cpp.shared_ptr_race`: partial, 61/117 applicable files examined; unexamined=56

## Limitations

## Incremental planning

- Base commit: `dee887d0a45ca2372338bdd033337809d3437b70`; changed paths: 0
- Execution: `full_scan_required`; fallback reason: `dependency_index_incomplete_and_detector_reuse_not_proven`
- Reused source files: 0; reused detector results: 0; cache-eligible recomputations/bypasses: 122. Full head source inventory and uncacheable detectors still ran.

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- Incremental mode preserves full source indexing. Only explicitly opted-in single-Blob detector results may be reused; cross-file dependency reuse remains disabled.
- `ohscanner.cpp.lifetime`: Detector Contract v1 remains unfrozen; this is a proposed implementation against the current M0 interface.
- `ohscanner.cpp.lifetime`: Dominating CFG paths, exception/early-return behavior, destructor timing, escaping aliases, and cross-function transfers are not modeled.
- `ohscanner.cpp.lifetime`: Empty findings are not proof of safety and are never benchmark misses.
- `ohscanner.cpp.lifetime`: First-party A algorithm: syntax candidates only; no CVE or validated vulnerability.
- `ohscanner.cpp.lifetime`: Lock ordering, condition variables, callbacks, and concurrent alias publication are not modeled.
- `ohscanner.cpp.lifetime`: Partial/failed/not_run parse coverage remains unknown and is never a benchmark miss.
- `ohscanner.cpp.lifetime`: Sync scope classification is descriptive; a lock does not preserve destroyed-object lifetime.
- `ohscanner.cpp.lifetime`: wmserver/src/starting_window.cpp: Unresolved rule symbols prevented complete owner/alias binding; the observation remains unknown.
- `ohscanner.cpp.lifetime`: wmserver/src/starting_window.cpp: partial; no safety verdict.
- `ohscanner.cpp.lifetime`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.lifetime`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.lifetime`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.lifetime`: INCOMPLETE COVERAGE: 56 applicable files not analyzed; inspect parsing.analysis_status and the coverage sidecar.
- `ohscanner.cpp.lifetime`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.
- `ohscanner.cpp.lifetime`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.cpp.shared_ptr_race`: Cross-function protocols, lock aliases, template instantiations and real product builds remain unknown; pairwise lexical evidence is not a global concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: First-party A algorithm: syntax candidates only; no CVE or validated vulnerability.
- `ohscanner.cpp.shared_ptr_race`: Mutex identity and atomic_load/atomic_store observations are lexical heuristics, not synchronization proofs.
- `ohscanner.cpp.shared_ptr_race`: No CFG, dataflow, cross-function escape, template instantiation, alias resolution or real product build is modeled.
- `ohscanner.cpp.shared_ptr_race`: completed covers only the selected cpp units under the declared narrow lexical scope; it is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/include/accessibility_connection.h: wmserver/include/accessibility_connection.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/include/animation_config.h: wmserver/include/animation_config.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/include/display_group_controller.h: wmserver/include/display_group_controller.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/include/display_group_info.h: wmserver/include/display_group_info.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/include/freeze_controller.h: wmserver/include/freeze_controller.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/include/input_window_monitor.h: wmserver/include/input_window_monitor.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/include/memory_guard.h: wmserver/include/memory_guard.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/include/minimize_app.h: wmserver/include/minimize_app.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/include/mock_session_manager_service.h: wmserver/include/mock_session_manager_service.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/include/utils/window_manager_service_utils.h: wmserver/include/utils/window_manager_service_utils.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/include/window_common_event.h: modeled accesses to 'wmserver/include/window_common_event.h::OHOS::WindowCommonEvent::eventHandler_' are constructor initialization only; stable-owner shape is not a concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: wmserver/include/window_dumper.h: wmserver/include/window_dumper.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/include/window_group_mgr.h: wmserver/include/window_group_mgr.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/include/window_layout_policy.h: wmserver/include/window_layout_policy.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/include/window_layout_policy_cascade.h: wmserver/include/window_layout_policy_cascade.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/include/window_layout_policy_tile.h: wmserver/include/window_layout_policy_tile.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/include/window_manager_config.h: wmserver/include/window_manager_config.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/include/window_node.h: modeled accesses to 'wmserver/include/window_node.h::OHOS::WindowNode::surfaceNode_' are constructor initialization only; stable-owner shape is not a concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: wmserver/include/window_node_state_machine.h: wmserver/include/window_node_state_machine.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/include/window_snapshot/snapshot_proxy.h: wmserver/include/window_snapshot/snapshot_proxy.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/include/window_snapshot/snapshot_stub.h: wmserver/include/window_snapshot/snapshot_stub.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/include/window_system_effect.h: wmserver/include/window_system_effect.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/include/window_zorder_policy.h: wmserver/include/window_zorder_policy.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/include/zidl/mock_session_manager_service_interface.h: wmserver/include/zidl/mock_session_manager_service_interface.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/include/zidl/session_manager_service_recover_proxy.h: wmserver/include/zidl/session_manager_service_recover_proxy.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/include/zidl/window_manager_stub.h: wmserver/include/zidl/window_manager_stub.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/src/accessibility_connection.cpp: wmserver/src/accessibility_connection.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/src/avoid_area_controller.cpp: wmserver/src/avoid_area_controller.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/src/memory_guard.cpp: wmserver/src/memory_guard.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/src/minimize_app.cpp: wmserver/src/minimize_app.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/src/utils/window_manager_service_utils.cpp: wmserver/src/utils/window_manager_service_utils.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/src/window_common_event.cpp: wmserver/src/window_common_event.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/src/window_dumper.cpp: wmserver/src/window_dumper.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/src/window_layout_policy_cascade.cpp: wmserver/src/window_layout_policy_cascade.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/src/window_manager_config.cpp: wmserver/src/window_manager_config.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/src/window_node_state_machine.cpp: wmserver/src/window_node_state_machine.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/src/window_snapshot/snapshot_stub.cpp: wmserver/src/window_snapshot/snapshot_stub.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/src/window_system_effect.cpp: wmserver/src/window_system_effect.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/src/window_zorder_policy.cpp: wmserver/src/window_zorder_policy.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: wmserver/src/zidl/session_manager_service_recover_proxy.cpp: wmserver/src/zidl/session_manager_service_recover_proxy.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.shared_ptr_race`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.shared_ptr_race`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.shared_ptr_race`: INCOMPLETE COVERAGE: 56 applicable files not analyzed; inspect parsing.analysis_status and the coverage sidecar.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `04307cac0b1cafc6983a551f5301dc0f5594967b77f9045f395f0e4df4524880`
- Language matching plans attempts; actual coverage remains in the results above.
