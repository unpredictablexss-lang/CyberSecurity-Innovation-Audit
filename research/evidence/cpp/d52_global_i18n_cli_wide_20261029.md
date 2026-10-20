# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/global_i18n`
- Pinned commit: `5e1210b17e720af2748685ee65bd480709c08a52`
- Git tree: `80d9a2200344cf348f3dd582c74e8c4aa7ed2969`
- Snapshot SHA-256: `0c3cb2d64e581d9ba8ff6c82adb851f6cb12b270bb17873f7a4e0fa6b5e84607`
- Source files indexed: 4
- Parsing coverage: `{"complete": 4}`
- Detector runs: 1
- Total unverified diagnostics: 0
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.shared_ptr_race` | completed | 4 | 4 | 0 | 0 | 0 | complete |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| — | — | — | — | No reported candidate; NOT proof of safety |

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
- `ohscanner.cpp.shared_ptr_race`: interfaces/ets/ani/intl/src/number_format_addon.cpp: interfaces/ets/ani/intl/src/number_format_addon.cpp: no class-member shared_ptr declaration was observed in the narrow lexical scope; absence of a finding is not a safe verdict.
- `ohscanner.cpp.shared_ptr_race`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.shared_ptr_race`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.shared_ptr_race`: Diagnostic does not establish vulnerability, reachability or security impact.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `1f639f7c9bf260ad0cc8a0ce505cce4284b10aeb31deb7fc9ddc5948845cea95`
- Language matching plans attempts; actual coverage remains in the results above.
