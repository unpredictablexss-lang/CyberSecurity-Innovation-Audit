# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/distributeddatamgr_preferences`
- Pinned commit: `bff9efd79afc0d7d1ed22a63ff355f1600404596`
- Git tree: `7761d9e273ae7007046ae115797f255e554523ae`
- Snapshot SHA-256: `8b09c534d8bbf596ce327a6eb1c1b7ffb4bf8d263148900bf1a8ecda879b2135`
- Source files indexed: 1
- Parsing coverage: `{"complete": 1}`
- Detector runs: 1
- Total unverified diagnostics: 25
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.shared_ptr_race` | completed | 1 | 1 | 0 | 0 | 25 | complete |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:d3ab21ac0a0bcaf8` | `test/native/fuzztest/dbpreferencesget_fuzzer/dbpreferencesget_fuzzer.cpp:43` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:693417e85a752f1e` | `test/native/fuzztest/dbpreferencesget_fuzzer/dbpreferencesget_fuzzer.cpp:48` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:61f87dc7e1b4f51f` | `test/native/fuzztest/dbpreferencesget_fuzzer/dbpreferencesget_fuzzer.cpp:50` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:24115590a1bb16c2` | `test/native/fuzztest/dbpreferencesget_fuzzer/dbpreferencesget_fuzzer.cpp:65` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:1e0e5b8f25f87b59` | `test/native/fuzztest/dbpreferencesget_fuzzer/dbpreferencesget_fuzzer.cpp:66` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:33e05c69e57671a2` | `test/native/fuzztest/dbpreferencesget_fuzzer/dbpreferencesget_fuzzer.cpp:74` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:b2e6f93bf7fcb707` | `test/native/fuzztest/dbpreferencesget_fuzzer/dbpreferencesget_fuzzer.cpp:75` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:7f73216448a6519b` | `test/native/fuzztest/dbpreferencesget_fuzzer/dbpreferencesget_fuzzer.cpp:83` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:ac15cd92b81ae3ca` | `test/native/fuzztest/dbpreferencesget_fuzzer/dbpreferencesget_fuzzer.cpp:91` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:8e7dfb458a975add` | `test/native/fuzztest/dbpreferencesget_fuzzer/dbpreferencesget_fuzzer.cpp:92` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:7eb4ec4ca0aaeebd` | `test/native/fuzztest/dbpreferencesget_fuzzer/dbpreferencesget_fuzzer.cpp:100` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:9e380eb76ec1ab12` | `test/native/fuzztest/dbpreferencesget_fuzzer/dbpreferencesget_fuzzer.cpp:108` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:7cb1d733fa09ecd0` | `test/native/fuzztest/dbpreferencesget_fuzzer/dbpreferencesget_fuzzer.cpp:109` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:325c1121397ce2c6` | `test/native/fuzztest/dbpreferencesget_fuzzer/dbpreferencesget_fuzzer.cpp:117` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:2607b0b172fb9c8f` | `test/native/fuzztest/dbpreferencesget_fuzzer/dbpreferencesget_fuzzer.cpp:125` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:34d91f654eb99897` | `test/native/fuzztest/dbpreferencesget_fuzzer/dbpreferencesget_fuzzer.cpp:126` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:c97882dfaa11aeb3` | `test/native/fuzztest/dbpreferencesget_fuzzer/dbpreferencesget_fuzzer.cpp:134` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:ae1c333cc9e5c0a1` | `test/native/fuzztest/dbpreferencesget_fuzzer/dbpreferencesget_fuzzer.cpp:142` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:87972f9c1630ab3d` | `test/native/fuzztest/dbpreferencesget_fuzzer/dbpreferencesget_fuzzer.cpp:143` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:4ab9639085e90264` | `test/native/fuzztest/dbpreferencesget_fuzzer/dbpreferencesget_fuzzer.cpp:151` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:1e9356bc5747910d` | `test/native/fuzztest/dbpreferencesget_fuzzer/dbpreferencesget_fuzzer.cpp:159` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:7b657db8132dfb56` | `test/native/fuzztest/dbpreferencesget_fuzzer/dbpreferencesget_fuzzer.cpp:160` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:9cd718b2d63d18ae` | `test/native/fuzztest/dbpreferencesget_fuzzer/dbpreferencesget_fuzzer.cpp:168` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:f76b00fa47f4a13b` | `test/native/fuzztest/dbpreferencesget_fuzzer/dbpreferencesget_fuzzer.cpp:176` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |
| `ohscanner.cpp.shared_ptr_race` | `ohscanner.cpp.shared_ptr_race:7dca39f01879dd07` | `test/native/fuzztest/dbpreferencesget_fuzzer/dbpreferencesget_fuzzer.cpp:177` | `ohcpp-shared-ptr-race-candidate-001` | synchronization_proof=unknown; thread_interleaving=unknown; product_build_context=unknown; security_impact=unknown |

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
- `ohscanner.cpp.shared_ptr_race`: test/native/fuzztest/dbpreferencesget_fuzzer/dbpreferencesget_fuzzer.cpp: pairwise analysis of 'test/native/fuzztest/dbpreferencesget_fuzzer/dbpreferencesget_fuzzer.cpp::OHOS::DBPreferencesGetFuzzTest::preferences_' leaves synchronization unproven for the mixed atomic/non-atomic synchronization protocol, different or one-sided mutexes, conditional/deferred locks, unresolved lock aliases or cross-function paths.
- `ohscanner.cpp.shared_ptr_race`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.shared_ptr_race`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.shared_ptr_race`: Diagnostic does not establish vulnerability, reachability or security impact.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `198e57836090abcce1643a40757fa39bbd5ee8d0c5b19dc01172213c9df245d0`
- Language matching plans attempts; actual coverage remains in the results above.
