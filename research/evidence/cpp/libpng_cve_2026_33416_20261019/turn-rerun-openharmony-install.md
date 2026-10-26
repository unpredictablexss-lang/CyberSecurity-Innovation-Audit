# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/third_party_libpng_install_output`
- Pinned commit: `ef42021d7597d3ca008c08567f0d698df39a4fa3`
- Git tree: `65f42cf3e86c5484802093f86e5f2babd623b573`
- Snapshot SHA-256: `4f8f76629faa78f2a4b4143236a3376c17a53acf1d9a1d6c80e62ad3e2172f81`
- Source files indexed: 4
- Parsing coverage: `{"partial": 4}`
- Detector runs: 1
- Total unverified diagnostics: 0
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.resource_lifetime` | blocked | 4 | 0 | 4 | 0 | 0 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| — | — | — | — | No reported candidate; NOT proof of safety |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.resource_lifetime`: partial, 0/4 applicable files examined; unexamined=4

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
- `ohscanner.cpp.resource_lifetime`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.
- `ohscanner.cpp.resource_lifetime`: Coverage incomplete or unsupported; do not infer safety.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `78179e48d01822a451149915df8035d40f6df2f5986420567c46646db7baac0f`
- Language matching plans attempts; actual coverage remains in the results above.
