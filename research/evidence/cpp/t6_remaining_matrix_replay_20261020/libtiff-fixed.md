# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `libtiff/libtiff`
- Pinned commit: `3e0dcf0ec651638b2bd849b2e6f3124b36890d99`
- Git tree: `77361ef7262189e16a2010b5c333f6b275d17f09`
- Snapshot SHA-256: `c7b380f2774adc947c493f919086e4a48cd4c0dfd1e6d6041e6e9ae2587817d5`
- Source files indexed: 2
- Parsing coverage: `{"partial": 2}`
- Detector runs: 1
- Total unverified diagnostics: 0
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.bounds` | blocked | 0 | 0 | 0 | 2 | 0 | blocked |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| — | — | — | — | No reported candidate; NOT proof of safety |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.bounds`: blocked, 0/2 applicable files examined; unexamined=2

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.cpp.bounds`: Absence of a finding is not a safe verdict; partial/failed source is unknown, not a miss.
- `ohscanner.cpp.bounds`: Candidate only: lexical array/copy facts do not prove exploitability or a product vulnerability.
- `ohscanner.cpp.bounds`: Pointer capacities, aliases, wrappers, interprocedural lengths, macros, template instantiation and full C++ CFG semantics remain unknown unless explicitly modeled.
- `ohscanner.cpp.bounds`: libtiff/tif_getimage.c: parse_status=partial; bounds coverage remains unknown.
- `ohscanner.cpp.bounds`: libtiff/tiffio.h: parse_status=partial; bounds coverage remains unknown.
- `ohscanner.cpp.bounds`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.bounds`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.bounds`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.bounds`: Coverage incomplete or unsupported; do not infer safety.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `66f275a0c6a945e2281f361d6c05efbde1afe457d775692eb652d43225d64ffe`
- Language matching plans attempts; actual coverage remains in the results above.
