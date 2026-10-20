# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/distributeddatamgr_preferences`
- Pinned commit: `bff9efd79afc0d7d1ed22a63ff355f1600404596`
- Git tree: `7761d9e273ae7007046ae115797f255e554523ae`
- Snapshot SHA-256: `beaf72b2c74be4bce5f636706ab1204316915c25250962e807d4048d194bd04d`
- Source files indexed: 3
- Parsing coverage: `{"complete": 3}`
- Detector runs: 1
- Total unverified diagnostics: 2
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.shared_ptr_race` | completed | 3 | 3 | 0 | 0 | 2 | complete |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:e0045f95e5674b5e` | `frameworks/js/napi/common/include/js_proxy.h:37` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:eb93be501066ca62` | `frameworks/js/napi/common/include/js_proxy.h:42` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.shared_ptr_race`: complete, 3/3 applicable files examined; unexamined=0

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
- `ohscanner.cpp.shared_ptr_race`: frameworks/js/napi/common/include/js_proxy.h: pairwise analysis of 'frameworks/js/napi/common/include/js_proxy.h::JSProxy::instance_' leaves synchronization unproven for the mixed atomic/non-atomic synchronization protocol, different or one-sided mutexes, conditional/deferred locks, unresolved lock aliases or cross-function paths.
- `ohscanner.cpp.shared_ptr_race`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.shared_ptr_race`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.shared_ptr_race`: Diagnostic does not establish vulnerability, reachability or security impact.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `c7f5c16f06e456208d961b9c533f5f5be71eec3177fcbeb0e4791f68b3cd7752`
- Language matching plans attempts; actual coverage remains in the results above.
