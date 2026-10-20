# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/multimedia_camera_framework`
- Pinned commit: `35445b57d739a41cb916330935e61f1e83d982ca`
- Git tree: `2907d1748b46897c49c8f8c253c49384294a6a7a`
- Snapshot SHA-256: `a66d6ddee99172586972b2bbd4145199908bbef4c72e7631f6eefea317252d34`
- Source files indexed: 2
- Parsing coverage: `{"complete": 2}`
- Detector runs: 1
- Total unverified diagnostics: 4
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.shared_ptr_race` | blocked | 2 | 1 | 1 | 0 | 4 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:bcf863af185f0d70` | `frameworks/taihe/include/camera_auto_ref_taihe.h:27` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:a2050b7fd2c9175a` | `frameworks/taihe/include/camera_auto_ref_taihe.h:43` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:4d2034de780a2ef1` | `frameworks/taihe/include/camera_auto_ref_taihe.h:48` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:ff05e7a3b49ec12d` | `frameworks/taihe/include/camera_auto_ref_taihe.h:52` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.shared_ptr_race`: partial, 1/2 applicable files examined; unexamined=1

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.cpp.shared_ptr_race`: Cross-function protocols, lock aliases, template instantiations and real product builds remain unknown; pairwise lexical evidence is not a global concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: First-party A algorithm: syntax candidates only; no CVE or validated vulnerability.
- `ohscanner.cpp.shared_ptr_race`: Mutex identity and atomic_load/atomic_store observations are lexical heuristics, not synchronization proofs.
- `ohscanner.cpp.shared_ptr_race`: No CFG, dataflow, cross-function escape, template instantiation, alias resolution or real product build is modeled.
- `ohscanner.cpp.shared_ptr_race`: common/utils/watch_dog.h: modeled non-atomic accesses to 'common/utils/watch_dog.h::OHOS::Watchdog::timeBroker_' are constructor initialization followed only by stable reads and do not form a potential conflicting pair in this narrow model.
- `ohscanner.cpp.shared_ptr_race`: completed covers only the selected cpp units under the declared narrow lexical scope; it is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: frameworks/taihe/include/camera_auto_ref_taihe.h: frameworks/taihe/include/camera_auto_ref_taihe.h: shared_ptr member 'callbackRef_' occurrence at line 36 is accessed through an unresolved object expression and remains unknown.
- `ohscanner.cpp.shared_ptr_race`: frameworks/taihe/include/camera_auto_ref_taihe.h: pairwise analysis of 'frameworks/taihe/include/camera_auto_ref_taihe.h::AutoRef::callbackRef_' leaves synchronization unproven for the mixed atomic/non-atomic synchronization protocol, different or one-sided mutexes, conditional/deferred locks, unresolved lock aliases or cross-function paths.
- `ohscanner.cpp.shared_ptr_race`: frameworks/taihe/include/camera_auto_ref_taihe.h: partial; no safety verdict.
- `ohscanner.cpp.shared_ptr_race`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.shared_ptr_race`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.shared_ptr_race`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.shared_ptr_race`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.
- `ohscanner.cpp.shared_ptr_race`: Coverage incomplete or unsupported; do not infer safety.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `6aeeb2f2d284a5ac552fd6b5eedd1f506caf833f23add6841e4358525124d991`
- Language matching plans attempts; actual coverage remains in the results above.
