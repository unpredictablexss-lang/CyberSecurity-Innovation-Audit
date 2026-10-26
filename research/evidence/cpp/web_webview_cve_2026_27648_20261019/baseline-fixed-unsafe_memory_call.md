# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `OpenHarmony-TPC/chromium_src`
- Pinned commit: `4cf313408de7b6d807465ea2bb22e434269b7c5e`
- Git tree: `a7769bf612be457e6e368f14ee355f3ea8ed2935`
- Snapshot SHA-256: `bac4ca6fad2618cbe23336337f4fd7c1ccbba9aaa9b0ca0d4e2cc0d08b434111`
- Source files indexed: 1
- Parsing coverage: `{"partial": 1}`
- Detector runs: 1
- Total unverified diagnostics: 0
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.unsafe_memory_call` | blocked | 0 | 0 | 0 | 1 | 0 | blocked |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| — | — | — | — | No reported candidate; NOT proof of safety |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.unsafe_memory_call`: blocked, 0/1 applicable files examined; unexamined=1

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.cpp.unsafe_memory_call`: arkweb/ohos_nweb/src/cef_delegate/nweb_handler_delegate.cc: parse_status=partial; unsafe-call coverage remains unknown.
- `ohscanner.cpp.unsafe_memory_call`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.unsafe_memory_call`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.unsafe_memory_call`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.unsafe_memory_call`: Coverage incomplete or unsupported; do not infer safety.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `f57df2bf90e7ebbfd6d37bfac6b9dfacda4b25425cbf440dd933cb1d56a92b63`
- Language matching plans attempts; actual coverage remains in the results above.
