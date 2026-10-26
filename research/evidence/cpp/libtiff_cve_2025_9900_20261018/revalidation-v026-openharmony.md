# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `OpenHarmony/third_party_libtiff`
- Pinned commit: `d4a0516c477dfbaf1153ae295893ab75aadd63d4`
- Git tree: `33beab3b3b50fe6678b1a74ed48ac3b69084c6ec`
- Snapshot SHA-256: `6a8d746b97e9914698d1511a4b8cee0f11b1d1dea665826d9d687025512ae835`
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
| `ohscanner.cpp.integer_bounds` | `ohscanner.cpp.integer_bounds:7042d256216970c2` | `libtiff/tif_getimage.c:621` | `ohcpp-integer-bounds-pointer-offset-underflow-candidate-004` | integer_range_and_signedness=unknown; overflow_guard_dominance=unknown; allocation_or_memory_consequence=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; cia_impact=missing |

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
- Plan SHA-256: `b8ca23eaffe51545722d3914905d5a591ec2dcba0e9d370ccc64e51a4192241a`
- Language matching plans attempts; actual coverage remains in the results above.
