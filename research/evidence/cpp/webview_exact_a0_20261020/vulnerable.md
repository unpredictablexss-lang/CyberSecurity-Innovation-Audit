# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/web_webview`
- Pinned commit: `a15cbf4ef20673cfcf1856bf40a723b3ce026564`
- Git tree: `03e16f6f4f2c33c2cd08e31c14e00be689230c39`
- Snapshot SHA-256: `df731397aeb53b11c868a5e8eda7306e0b8151e897fc28d2604481aed8874958`
- Source files indexed: 1
- Parsing coverage: `{"partial": 1}`
- Detector runs: 1
- Total unverified diagnostics: 0
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.bounds` | blocked | 0 | 0 | 0 | 1 | 0 | blocked |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| — | — | — | — | No reported candidate; NOT proof of safety |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.bounds`: blocked, 0/1 applicable files examined; unexamined=1

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.cpp.bounds`: Absence of a finding is not a safe verdict; partial/failed source is unknown, not a miss.
- `ohscanner.cpp.bounds`: Candidate only: lexical array/copy facts do not prove exploitability or a product vulnerability.
- `ohscanner.cpp.bounds`: Pointer capacities, aliases, wrappers, interprocedural lengths, macros, template instantiation and full C++ CFG semantics remain unknown unless explicitly modeled.
- `ohscanner.cpp.bounds`: arkweb/ohos_nweb/src/cef_delegate/nweb_handler_delegate.cc: parse_status=partial; bounds coverage remains unknown.
- `ohscanner.cpp.bounds`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.bounds`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.bounds`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.bounds`: Coverage incomplete or unsupported; do not infer safety.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `6f496fca945c8c5808e5734f574517c58d5b488ae56c5c09f782e8cf22e613ae`
- Language matching plans attempts; actual coverage remains in the results above.
