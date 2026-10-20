# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/arkcompiler_ets_runtime`
- Pinned commit: `cae11f121c030a90ba41d8e4d866f91292f25892`
- Git tree: `61ff01d9a06b4186125a04e2b790e07640f57198`
- Snapshot SHA-256: `3dbcf1026af41de48c9ed318a2fab2d1d1e3e6f30b922899bf34dbe911d9e512`
- Source files indexed: 1
- Parsing coverage: `{"complete": 1}`
- Detector runs: 1
- Total unverified diagnostics: 1
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.integer_bounds` | completed | 1 | 1 | 0 | 0 | 1 | complete |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.cpp.integer_bounds` | `ohscanner.cpp.integer_bounds:b7b2f77b4f18fb3d` | `ecmascript/base/atomic_helper.cpp:71` | `ohcpp-integer-bounds-narrow-index-candidate-003` | integer_range_and_signedness=unknown; overflow_guard_dominance=unknown; allocation_or_memory_consequence=unknown; cross_function_and_macro_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; cia_impact=missing |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.integer_bounds`: complete, 1/1 applicable files examined; unexamined=0

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.cpp.integer_bounds`: A guarded or unknown expression is not a safe verdict; partial/failed source remains unknown.
- `ohscanner.cpp.integer_bounds`: Candidate only: lexical integer arithmetic does not prove allocation undersizing or product impact.
- `ohscanner.cpp.integer_bounds`: Signedness, promotions, macro constants, overflow intrinsics, templates and interprocedural range facts remain unknown unless explicitly modeled.
- `ohscanner.cpp.integer_bounds`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.integer_bounds`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.integer_bounds`: Diagnostic does not establish vulnerability, reachability or security impact.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `6925bb9c7ff714ab02c2f2dad2b0ebcaaa44ae739f688659e6b5e688df46e740`
- Language matching plans attempts; actual coverage remains in the results above.
