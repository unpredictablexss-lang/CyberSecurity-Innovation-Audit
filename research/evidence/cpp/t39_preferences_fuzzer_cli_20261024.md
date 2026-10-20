# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/distributeddatamgr_preferences`
- Pinned commit: `bff9efd79afc0d7d1ed22a63ff355f1600404596`
- Git tree: `7761d9e273ae7007046ae115797f255e554523ae`
- Snapshot SHA-256: `54c6c84c51f3b30669dc7962fc776207532fafa0fa3d0866dd792e3417fe9f75`
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
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:c8d862df309bc6e8` | `test/native/fuzztest/preferences_fuzzer/preferences_fuzzer.cpp:46` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:e06970342e1589e5` | `test/native/fuzztest/preferences_fuzzer/preferences_fuzzer.cpp:51` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:d45a2ab1ccd87b57` | `test/native/fuzztest/preferences_fuzzer/preferences_fuzzer.cpp:53` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:04d7f855cf838e0b` | `test/native/fuzztest/preferences_fuzzer/preferences_fuzzer.cpp:68` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:cb9638502cb08b2f` | `test/native/fuzztest/preferences_fuzzer/preferences_fuzzer.cpp:69` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:a70e637212a6b076` | `test/native/fuzztest/preferences_fuzzer/preferences_fuzzer.cpp:77` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:e5f12e89e2779b69` | `test/native/fuzztest/preferences_fuzzer/preferences_fuzzer.cpp:78` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:3a308d9708b0802e` | `test/native/fuzztest/preferences_fuzzer/preferences_fuzzer.cpp:86` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:3fe8ca30d4133ecb` | `test/native/fuzztest/preferences_fuzzer/preferences_fuzzer.cpp:87` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:9f5b14f9a7844537` | `test/native/fuzztest/preferences_fuzzer/preferences_fuzzer.cpp:95` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:6258aa5e23a470ef` | `test/native/fuzztest/preferences_fuzzer/preferences_fuzzer.cpp:96` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:18aee91f72dc1998` | `test/native/fuzztest/preferences_fuzzer/preferences_fuzzer.cpp:104` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:8918a41536d3f1ca` | `test/native/fuzztest/preferences_fuzzer/preferences_fuzzer.cpp:105` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:ee90232ed4af5aa3` | `test/native/fuzztest/preferences_fuzzer/preferences_fuzzer.cpp:113` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:68cf0b81f60deac9` | `test/native/fuzztest/preferences_fuzzer/preferences_fuzzer.cpp:114` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:c09682270995ec1c` | `test/native/fuzztest/preferences_fuzzer/preferences_fuzzer.cpp:115` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:5028826f569067e8` | `test/native/fuzztest/preferences_fuzzer/preferences_fuzzer.cpp:124` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:a88fb238c64aa7e3` | `test/native/fuzztest/preferences_fuzzer/preferences_fuzzer.cpp:125` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:4bacb2ad7ca38c0b` | `test/native/fuzztest/preferences_fuzzer/preferences_fuzzer.cpp:126` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |

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
- `ohscanner.cpp.shared_ptr_race`: test/native/fuzztest/preferences_fuzzer/preferences_fuzzer.cpp: pairwise analysis of 'test/native/fuzztest/preferences_fuzzer/preferences_fuzzer.cpp::OHOS::PreferencesFuzzTest::Preferences_' leaves synchronization unproven for the mixed atomic/non-atomic synchronization protocol, different or one-sided mutexes, conditional/deferred locks, unresolved lock aliases or cross-function paths.
- `ohscanner.cpp.shared_ptr_race`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.shared_ptr_race`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.shared_ptr_race`: Diagnostic does not establish vulnerability, reachability or security impact.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `255ee2296241af4601539ddb5ed03bb16db65fd2cfe34ce681959f5c6df23a69`
- Language matching plans attempts; actual coverage remains in the results above.
