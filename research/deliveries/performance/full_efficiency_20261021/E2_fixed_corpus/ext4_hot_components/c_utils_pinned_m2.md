# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/commonlibrary_c_utils`
- Pinned commit: `b807d3dadb7dbb7639fe85b3a5f72da18d318da2`
- Git tree: `52b42d41ed091f7dcae37c4ce3a0d95b6fb1f16d`
- Snapshot SHA-256: `9a87a156afb5c2edc0994539ff43e468c05b39eea7f3b958866e1dae0a1e454d`
- Source files indexed: 123
- Parsing coverage: `{"complete": 94, "partial": 29}`
- Detector runs: 2
- Total unverified diagnostics: 0
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.lifetime` | blocked | 94 | 92 | 2 | 29 | 0 | partial |
| `ohscanner.cpp.shared_ptr_race` | completed | 94 | 94 | 0 | 29 | 0 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| — | — | — | — | No reported candidate; NOT proof of safety |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.lifetime`: partial, 92/123 applicable files examined; unexamined=31
- `ohscanner.cpp.shared_ptr_race`: partial, 94/123 applicable files examined; unexamined=29

## Limitations

## Incremental planning

- Base commit: `8044daa1040218b6b6b2088c3df334d5ae047c1b`; changed paths: 3
- Execution: `full_source_index_with_verified_per_file_result_reuse`; fallback reason: `cross_file_dependency_reuse_unproven; declared_source_blob_results_reused`
- Reused source files: 94; reused detector results: 186; cache-eligible recomputations/bypasses: 2. Full head source inventory and uncacheable detectors still ran.

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
- `ohscanner.cpp.lifetime`: base/test/benchmarktest/event_benchmark_test/event_benchmark_test.cpp: Unresolved rule symbols prevented complete owner/alias binding; the observation remains unknown.
- `ohscanner.cpp.lifetime`: base/test/benchmarktest/event_benchmark_test/event_benchmark_test.cpp: partial; no safety verdict.
- `ohscanner.cpp.lifetime`: base/test/benchmarktest/singleton_benchmark_test/singleton_benchmark_test.cpp: Unresolved rule symbols prevented complete owner/alias binding; the observation remains unknown.
- `ohscanner.cpp.lifetime`: base/test/benchmarktest/singleton_benchmark_test/singleton_benchmark_test.cpp: partial; no safety verdict.
- `ohscanner.cpp.lifetime`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.lifetime`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.lifetime`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.lifetime`: INCOMPLETE COVERAGE: 29 applicable files not analyzed; inspect parsing.analysis_status and the coverage sidecar.
- `ohscanner.cpp.lifetime`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.
- `ohscanner.cpp.lifetime`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.cpp.shared_ptr_race`: Cross-function protocols, lock aliases, template instantiations and real product builds remain unknown; pairwise lexical evidence is not a global concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: First-party A algorithm: syntax candidates only; no CVE or validated vulnerability.
- `ohscanner.cpp.shared_ptr_race`: Mutex identity and atomic_load/atomic_store observations are lexical heuristics, not synchronization proofs.
- `ohscanner.cpp.shared_ptr_race`: No CFG, dataflow, cross-function escape, template instantiation, alias resolution or real product build is modeled.
- `ohscanner.cpp.shared_ptr_race`: base/include/common_errors.h: base/include/common_errors.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/include/common_event_sys_errors.h: base/include/common_event_sys_errors.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/include/common_mapped_file_errors.h: base/include/common_mapped_file_errors.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/include/common_timer_errors.h: base/include/common_timer_errors.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/include/datetime_ex.h: base/include/datetime_ex.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/include/directory_ex.h: base/include/directory_ex.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/include/directory_ex_inner.h: base/include/directory_ex_inner.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/include/errors.h: base/include/errors.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/include/file_ex.h: base/include/file_ex.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/include/flat_obj.h: base/include/flat_obj.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/include/io_event_common.h: base/include/io_event_common.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/include/io_event_handler.h: base/include/io_event_handler.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/include/mapped_file.h: base/include/mapped_file.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/include/nocopyable.h: base/include/nocopyable.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/include/parcel.h: base/include/parcel.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/include/pubdef.h: base/include/pubdef.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/include/refbase.h: base/include/refbase.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/include/rwlock.h: base/include/rwlock.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/include/safe_block_queue.h: base/include/safe_block_queue.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/include/safe_queue.h: base/include/safe_queue.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/include/semaphore_ex.h: base/include/semaphore_ex.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/include/singleton.h: modeled accesses to 'base/include/singleton.h::OHOS::DelayedSingleton::instance_' use only the atomic shared_ptr API; this narrow atomic-only shape is not a concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: base/include/sorted_vector.h: base/include/sorted_vector.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/include/string_ex.h: base/include/string_ex.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/include/thread_ex.h: base/include/thread_ex.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/include/thread_pool.h: base/include/thread_pool.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/src/datetime_ex.cpp: base/src/datetime_ex.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/src/directory_ex.cpp: base/src/directory_ex.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/src/event_handler.cpp: base/src/event_handler.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/src/event_handler.h: base/src/event_handler.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/src/file_ex.cpp: base/src/file_ex.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/src/io_event_epoll.h: base/src/io_event_epoll.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/src/io_event_handler.cpp: base/src/io_event_handler.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/src/io_event_reactor.cpp: base/src/io_event_reactor.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/src/mapped_file.cpp: base/src/mapped_file.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/src/parcel.cpp: base/src/parcel.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/src/refbase.cpp: base/src/refbase.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/src/rwlock.cpp: base/src/rwlock.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/src/semaphore_ex.cpp: base/src/semaphore_ex.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/src/string_ex.cpp: base/src/string_ex.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/src/thread_ex.cpp: base/src/thread_ex.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/src/thread_pool.cpp: base/src/thread_pool.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/src/timer.cpp: base/src/timer.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/src/timer_event_handler.cpp: base/src/timer_event_handler.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/src/timer_event_handler.h: base/src/timer_event_handler.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/src/unicode_ex.cpp: base/src/unicode_ex.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/src/unicode_ex.h: base/src/unicode_ex.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/src/utils_log.h: base/src/utils_log.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/test/benchmarktest/ashemem_benchmark_test/ashemem_benchmark_test.cpp: base/test/benchmarktest/ashemem_benchmark_test/ashemem_benchmark_test.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/test/benchmarktest/benchmark_assert.h: base/test/benchmarktest/benchmark_assert.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/test/benchmarktest/benchmark_log.h: base/test/benchmarktest/benchmark_log.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/test/benchmarktest/datatime_benchmark_test/datatime_benchmark_test.cpp: base/test/benchmarktest/datatime_benchmark_test/datatime_benchmark_test.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/test/benchmarktest/directory_benchmark_test/directory_benchmark_test.cpp: base/test/benchmarktest/directory_benchmark_test/directory_benchmark_test.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/test/benchmarktest/file_benchmark_test/file_benchmark_test.cpp: base/test/benchmarktest/file_benchmark_test/file_benchmark_test.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/test/benchmarktest/mapped_benchmark_test/mapped_benchmark_test.cpp: base/test/benchmarktest/mapped_benchmark_test/mapped_benchmark_test.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/test/benchmarktest/parcel_benchmark_test/parcel_benchmark_test.cpp: base/test/benchmarktest/parcel_benchmark_test/parcel_benchmark_test.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/test/benchmarktest/refbase_benchmark_test/refbase_benchmark_test.cpp: base/test/benchmarktest/refbase_benchmark_test/refbase_benchmark_test.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/test/benchmarktest/rwlock_benchmark_test/rwlock_benchmark_test.cpp: base/test/benchmarktest/rwlock_benchmark_test/rwlock_benchmark_test.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/test/benchmarktest/safe_block_queue_benchmark_test/safe_block_queue_benchmark_test.cpp: base/test/benchmarktest/safe_block_queue_benchmark_test/safe_block_queue_benchmark_test.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/test/benchmarktest/safe_block_queue_tracking_benchmark_test/safe_block_queue_tracking_benchmark_test.cpp: base/test/benchmarktest/safe_block_queue_tracking_benchmark_test/safe_block_queue_tracking_benchmark_test.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/test/benchmarktest/safe_map_benchmark_test/safe_map_benchmark_test.cpp: base/test/benchmarktest/safe_map_benchmark_test/safe_map_benchmark_test.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/test/benchmarktest/safe_queue_benchmark_test/safe_queue_benchmark_test.cpp: base/test/benchmarktest/safe_queue_benchmark_test/safe_queue_benchmark_test.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/test/benchmarktest/sorted_vector_benchmark_test/sorted_vector_benchmark_test.cpp: base/test/benchmarktest/sorted_vector_benchmark_test/sorted_vector_benchmark_test.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/test/benchmarktest/string_benchmark_test/string_benchmark_test.cpp: base/test/benchmarktest/string_benchmark_test/string_benchmark_test.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/test/benchmarktest/thread_benchmark_test/thread_benchmark_test.cpp: base/test/benchmarktest/thread_benchmark_test/thread_benchmark_test.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/test/benchmarktest/thread_pool_benchmark_test/thread_pool_benchmark_test.cpp: base/test/benchmarktest/thread_pool_benchmark_test/thread_pool_benchmark_test.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/test/benchmarktest/timer_benchmark_test/timer_benchmark_test.cpp: base/test/benchmarktest/timer_benchmark_test/timer_benchmark_test.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/test/benchmarktest/unique_fd_benchmark_test/unique_fd_benchmark_test.cpp: base/test/benchmarktest/unique_fd_benchmark_test/unique_fd_benchmark_test.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/test/fuzztest/ashmem_fuzzer/ashmem_fuzzer.cpp: base/test/fuzztest/ashmem_fuzzer/ashmem_fuzzer.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/test/fuzztest/ashmem_fuzzer/ashmem_fuzzer.h: base/test/fuzztest/ashmem_fuzzer/ashmem_fuzzer.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/test/fuzztest/directory_fuzzer/directory_fuzzer.cpp: base/test/fuzztest/directory_fuzzer/directory_fuzzer.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/test/fuzztest/directory_fuzzer/directory_fuzzer.h: base/test/fuzztest/directory_fuzzer/directory_fuzzer.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/test/fuzztest/fuzz_log.h: base/test/fuzztest/fuzz_log.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/test/fuzztest/parcel_fuzzer/parcel_fuzzer.h: base/test/fuzztest/parcel_fuzzer/parcel_fuzzer.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/test/fuzztest/refbase_fuzzer/refbase_fuzzer.cpp: base/test/fuzztest/refbase_fuzzer/refbase_fuzzer.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/test/fuzztest/refbase_fuzzer/refbase_fuzzer.h: base/test/fuzztest/refbase_fuzzer/refbase_fuzzer.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/test/fuzztest/string_fuzzer/string_fuzzer.cpp: base/test/fuzztest/string_fuzzer/string_fuzzer.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/test/fuzztest/string_fuzzer/string_fuzzer.h: base/test/fuzztest/string_fuzzer/string_fuzzer.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/test/fuzztest/thread_fuzzer/thread_fuzzer.cpp: base/test/fuzztest/thread_fuzzer/thread_fuzzer.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/test/fuzztest/thread_fuzzer/thread_fuzzer.h: base/test/fuzztest/thread_fuzzer/thread_fuzzer.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/test/fuzztest/timer_fuzzer/timer_fuzzer.cpp: base/test/fuzztest/timer_fuzzer/timer_fuzzer.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: base/test/fuzztest/timer_fuzzer/timer_fuzzer.h: base/test/fuzztest/timer_fuzzer/timer_fuzzer.h: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: completed covers only the selected cpp units under the declared narrow lexical scope; it is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.shared_ptr_race`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.shared_ptr_race`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.shared_ptr_race`: INCOMPLETE COVERAGE: 29 applicable files not analyzed; inspect parsing.analysis_status and the coverage sidecar.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `4092c252613293c58ef769aeedddc7b1fa0de31975408dd2a4ba3a390407a0bd`
- Language matching plans attempts; actual coverage remains in the results above.
