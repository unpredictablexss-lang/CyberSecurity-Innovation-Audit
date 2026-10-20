# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/security_huks`
- Pinned commit: `4ae4e0db461f137672719d43ffc6c5b1b6c05be8`
- Git tree: `9c922a60d815a34eb96c060274ed863fd3a6fea8`
- Snapshot SHA-256: `8272abad072b6bb40bcb3f3763b4ea624a02b68fe623f7c3ecdd01a44791da03`
- Source files indexed: 1
- Parsing coverage: `{"complete": 1}`
- Detector runs: 1
- Total unverified diagnostics: 0
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.shared_ptr_race` | completed | 1 | 1 | 0 | 0 | 0 | complete |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| — | — | — | — | No reported candidate; NOT proof of safety |

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
- `ohscanner.cpp.shared_ptr_race`: services/huks_standard/huks_service/extension/ability_native/inc/hks_crypto_ext_stub_impl.h: modeled accesses to 'services/huks_standard/huks_service/extension/ability_native/inc/hks_crypto_ext_stub_impl.h::OHOS::HksCryptoExtStubImpl::extension_' are constructor initialization only; stable-owner shape is not a concurrency proof.
- `ohscanner.cpp.shared_ptr_race`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.shared_ptr_race`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.shared_ptr_race`: Diagnostic does not establish vulnerability, reachability or security impact.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `74ee7e4f7228400917f0b4fb19be5599bfb96770ab2abff16dd01a4888710cc3`
- Language matching plans attempts; actual coverage remains in the results above.
