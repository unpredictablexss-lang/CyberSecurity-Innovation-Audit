# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/distributeddatamgr_preferences`
- Pinned commit: `bff9efd79afc0d7d1ed22a63ff355f1600404596`
- Git tree: `7761d9e273ae7007046ae115797f255e554523ae`
- Snapshot SHA-256: `c287af8f7d2c3c469733252692e593e7f9eae4267a2430df2b9fecbf734131c4`
- Source files indexed: 1
- Parsing coverage: `{"complete": 1}`
- Detector runs: 1
- Total unverified diagnostics: 19
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.shared_ptr_race` | completed | 1 | 1 | 0 | 0 | 19 | complete |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:81b94b63ab56506c` | `test/native/fuzztest/dbpreferences_fuzzer/dbpreferences_fuzzer.cpp:43` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:2b48e26f0f1f8db2` | `test/native/fuzztest/dbpreferences_fuzzer/dbpreferences_fuzzer.cpp:48` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:d52382ce60e23dd3` | `test/native/fuzztest/dbpreferences_fuzzer/dbpreferences_fuzzer.cpp:50` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:e018ece329b53813` | `test/native/fuzztest/dbpreferences_fuzzer/dbpreferences_fuzzer.cpp:65` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:32b09d121dae57aa` | `test/native/fuzztest/dbpreferences_fuzzer/dbpreferences_fuzzer.cpp:66` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:c4eb1d6fb40d59b5` | `test/native/fuzztest/dbpreferences_fuzzer/dbpreferences_fuzzer.cpp:74` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:2542a26133b617e1` | `test/native/fuzztest/dbpreferences_fuzzer/dbpreferences_fuzzer.cpp:75` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:d4db1a1b8ac8e87a` | `test/native/fuzztest/dbpreferences_fuzzer/dbpreferences_fuzzer.cpp:83` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:cc5e3053794992ec` | `test/native/fuzztest/dbpreferences_fuzzer/dbpreferences_fuzzer.cpp:84` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:4eb09648862c68a8` | `test/native/fuzztest/dbpreferences_fuzzer/dbpreferences_fuzzer.cpp:92` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:3e5cce5d642651d1` | `test/native/fuzztest/dbpreferences_fuzzer/dbpreferences_fuzzer.cpp:93` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:50c93b4762a41541` | `test/native/fuzztest/dbpreferences_fuzzer/dbpreferences_fuzzer.cpp:101` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:2b77a33d55a575fc` | `test/native/fuzztest/dbpreferences_fuzzer/dbpreferences_fuzzer.cpp:102` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:ca194fbf605dc358` | `test/native/fuzztest/dbpreferences_fuzzer/dbpreferences_fuzzer.cpp:110` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:279a12bd13cd499c` | `test/native/fuzztest/dbpreferences_fuzzer/dbpreferences_fuzzer.cpp:111` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:2939e3de23a444ef` | `test/native/fuzztest/dbpreferences_fuzzer/dbpreferences_fuzzer.cpp:112` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:b662b450001c19f4` | `test/native/fuzztest/dbpreferences_fuzzer/dbpreferences_fuzzer.cpp:121` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:204b5bc0a8b23f85` | `test/native/fuzztest/dbpreferences_fuzzer/dbpreferences_fuzzer.cpp:122` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:b8d0819e33221773` | `test/native/fuzztest/dbpreferences_fuzzer/dbpreferences_fuzzer.cpp:123` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.shared_ptr_race`: complete, 1/1 applicable files examined; unexamined=0

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
- `ohscanner.cpp.shared_ptr_race`: test/native/fuzztest/dbpreferences_fuzzer/dbpreferences_fuzzer.cpp: pairwise analysis of 'test/native/fuzztest/dbpreferences_fuzzer/dbpreferences_fuzzer.cpp::OHOS::DBPreferencesFuzzTest::preferences_' leaves synchronization unproven for the mixed atomic/non-atomic synchronization protocol, different or one-sided mutexes, conditional/deferred locks, unresolved lock aliases or cross-function paths.
- `ohscanner.cpp.shared_ptr_race`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.shared_ptr_race`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.shared_ptr_race`: Diagnostic does not establish vulnerability, reachability or security impact.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `208aa406741a654e5e8c3da30a947b5b0afd5d6623c67438d43af05cbe1c0962`
- Language matching plans attempts; actual coverage remains in the results above.
