# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `osgeo/libtiff`
- Pinned commit: `9dff73bebc5661f2dace6f16e14cf9e857172f4e`
- Git tree: `986499c84247e9a1f49560128bbe7580d8ebea1a`
- Snapshot SHA-256: `dda2fe1af73132372d00a491714b80dcf51a6056a1acc0e60259fc4e922a748a`
- Source files indexed: 2
- Parsing coverage: `{"partial": 2}`
- Detector runs: 1
- Total unverified diagnostics: 1
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.integer_bounds` | blocked | 2 | 0 | 2 | 0 | 1 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.cpp.integer_bounds` | `ohscanner.cpp.integer_bounds:814ab31e43b51233` | `libtiff/tif_getimage.c:621` | `ohcpp-integer-bounds-pointer-offset-underflow-candidate-004` | integer_range_and_signedness=unknown; overflow_guard_dominance=unknown; allocation_or_memory_consequence=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; cia_impact=missing |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.integer_bounds`: partial, 0/2 applicable files examined; unexamined=2

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.cpp.integer_bounds`: A guarded or unknown expression is not a safe verdict; partial/failed source remains unknown.
- `ohscanner.cpp.integer_bounds`: Candidate only: lexical integer arithmetic does not prove allocation undersizing or product impact.
- `ohscanner.cpp.integer_bounds`: Signedness, promotions, macro constants, overflow intrinsics, templates and interprocedural range facts remain unknown unless explicitly modeled.
- `ohscanner.cpp.integer_bounds`: libtiff/tif_getimage.c: parser reported partial syntax; only the bounded pointer-offset underflow shape was inspected.
- `ohscanner.cpp.integer_bounds`: libtiff/tiffio.h: parser reported partial syntax; only the bounded pointer-offset underflow shape was inspected.
- `ohscanner.cpp.integer_bounds`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.integer_bounds`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.integer_bounds`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.integer_bounds`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.
- `ohscanner.cpp.integer_bounds`: Coverage incomplete or unsupported; do not infer safety.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `5cee81bc4dfb0f76a07e903dcbb3a15592f857fa7aa89d50f42e692cd79bcdc0`
- Language matching plans attempts; actual coverage remains in the results above.
