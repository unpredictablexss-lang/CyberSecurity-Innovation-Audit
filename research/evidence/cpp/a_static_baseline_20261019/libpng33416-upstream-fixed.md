# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `libpng/libpng`
- Pinned commit: `d5515b5b8be3901aac04e5bd8bd5c89f287bcd33`
- Git tree: `a28bb962645843af84063c77f574f6d88da79f76`
- Snapshot SHA-256: `21cfd3bac010b1ba63611630ac8381487a9455c24591618cb16bb52e0a600eae`
- Source files indexed: 4
- Parsing coverage: `{"partial": 4}`
- Detector runs: 1
- Total unverified diagnostics: 0
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.resource_lifetime` | blocked | 0 | 0 | 0 | 4 | 0 | blocked |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| — | — | — | — | No reported candidate; NOT proof of safety |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.resource_lifetime`: blocked, 0/4 applicable files examined; unexamined=4

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.cpp.resource_lifetime`: png.c: parse_status=partial; resource lifetime remains unknown.
- `ohscanner.cpp.resource_lifetime`: pngread.c: parse_status=partial; resource lifetime remains unknown.
- `ohscanner.cpp.resource_lifetime`: pngrtran.c: parse_status=partial; resource lifetime remains unknown.
- `ohscanner.cpp.resource_lifetime`: pngset.c: parse_status=partial; resource lifetime remains unknown.
- `ohscanner.cpp.resource_lifetime`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.resource_lifetime`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.resource_lifetime`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.resource_lifetime`: Coverage incomplete or unsupported; do not infer safety.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `08ccb371f37b16d64c572e8139ccd8f95489a6deb72d116ecd8aa63a286b775c`
- Language matching plans attempts; actual coverage remains in the results above.
