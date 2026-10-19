# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/hiviewdfx_faultloggerd`
- Pinned commit: `50c7dffc057a32987d5eeb7626c20e1b3717c77b`
- Git tree: `8b54f17921ba15ff306bcbef280078003a7b1055`
- Snapshot SHA-256: `1cfa53a9e3c41f2ad9f37511e63d4298187f3737dfd2ce426139fe58fb26d8d7`
- Source files indexed: 4
- Parsing coverage: `{"complete": 4}`
- Detector runs: 1
- Total unverified diagnostics: 7
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.shared_ptr_race` | completed | 4 | 4 | 0 | 0 | 7 | complete |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:e8bc5bf3de23df86` | `tools/process_dump/dfx_process.h:55` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:b95bbc62436d4be7` | `tools/process_dump/dfx_process.h:60` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:93f311701435a067` | `tools/process_dump/dfx_process.h:69` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:6d5edfb3cf9c579b` | `tools/process_dump/dfx_process.h:74` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:359b91f5f5ac9612` | `tools/process_dump/dfx_thread.h:64` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:4c18713fd27833ff` | `tools/process_dump/dfx_thread.h:69` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:b93d88a86d9485b8` | `tools/process_dump/minidump_parser/include/minidump_stream.h:76` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.shared_ptr_race`: complete, 4/4 applicable files examined; unexamined=0

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.cpp.shared_ptr_race`: Cross-function protocols, lock aliases, template instantiations and real product builds remain unknown; pairwise lexical evidence is not a global concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: First-party A algorithm: syntax candidates only; no CVE or validated vulnerability.
- `ohscanner.cpp.shared_ptr_race`: Mutex identity and atomic_load/atomic_store observations are lexical heuristics, not synchronization proofs.
- `ohscanner.cpp.shared_ptr_race`: No CFG, dataflow, cross-function escape, template instantiation, alias resolution or real product build is modeled.
- `ohscanner.cpp.shared_ptr_race`: completed covers only the selected cpp units under the declared narrow lexical scope; it is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: tools/process_dump/dfx_process.h: pairwise analysis of 'tools/process_dump/dfx_process.h::OHOS::DfxProcess::keyThread_' leaves synchronization unproven for the mixed atomic/non-atomic synchronization protocol, different or one-sided mutexes, conditional/deferred locks, unresolved lock aliases or cross-function paths.
- `ohscanner.cpp.shared_ptr_race`: tools/process_dump/dfx_process.h: pairwise analysis of 'tools/process_dump/dfx_process.h::OHOS::DfxProcess::regs_' leaves synchronization unproven for the mixed atomic/non-atomic synchronization protocol, different or one-sided mutexes, conditional/deferred locks, unresolved lock aliases or cross-function paths.
- `ohscanner.cpp.shared_ptr_race`: tools/process_dump/dfx_thread.h: pairwise analysis of 'tools/process_dump/dfx_thread.h::OHOS::DfxThread::stackBuf_' leaves synchronization unproven for the mixed atomic/non-atomic synchronization protocol, different or one-sided mutexes, conditional/deferred locks, unresolved lock aliases or cross-function paths.
- `ohscanner.cpp.shared_ptr_race`: tools/process_dump/minidump_parser/include/minidump_parser.h: modeled accesses to 'tools/process_dump/minidump_parser/include/minidump_parser.h::OHOS::MinidumpParser::streamMap_' are constructor initialization only; stable-owner shape is not a concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: tools/process_dump/minidump_parser/include/minidump_parser.h: modeled accesses to 'tools/process_dump/minidump_parser/include/minidump_parser.h::OHOS::MinidumpParser::stream_' are constructor initialization only; stable-owner shape is not a concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: tools/process_dump/minidump_parser/include/minidump_parser.h: modeled non-atomic accesses to 'tools/process_dump/minidump_parser/include/minidump_parser.h::OHOS::MinidumpParser::minidumpSubject_' are constructor initialization followed only by stable reads and do not form a potential conflicting pair in this narrow model.
- `ohscanner.cpp.shared_ptr_race`: tools/process_dump/minidump_parser/include/minidump_stream.h: pairwise analysis of 'tools/process_dump/minidump_parser/include/minidump_stream.h::OHOS::MinidumpContext::arm64Context_' leaves synchronization unproven for the mixed atomic/non-atomic synchronization protocol, different or one-sided mutexes, conditional/deferred locks, unresolved lock aliases or cross-function paths.
- `ohscanner.cpp.shared_ptr_race`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.shared_ptr_race`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.shared_ptr_race`: Diagnostic does not establish vulnerability, reachability or security impact.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `8442ab22b9e2e36a74e6370934b71a7d39534179e8709f86fcdd256c708ba849`
- Language matching plans attempts; actual coverage remains in the results above.
