# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `fixture/disclosed-cves`
- Pinned commit: `fb1309f75f13affdf8ca5c93ab88ba87704e4e49`
- Git tree: `736021ede126beffc4b65a364adda8004f1b28c7`
- Snapshot SHA-256: `9debf7abd39fa333d24025da7443f8b8f8fe576acecff15b05906db8fef0f7fc`
- Source files indexed: 3
- Parsing coverage: `{"complete": 3}`
- Detector runs: 5
- Total unverified diagnostics: 2
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.bounds` | completed | 3 | 3 | 0 | 0 | 0 | complete |
| `ohscanner.cpp.integer_bounds` | completed | 3 | 3 | 0 | 0 | 0 | complete |
| `ohscanner.cpp.null_dereference` | blocked | 3 | 2 | 1 | 0 | 2 | partial |
| `ohscanner.cpp.resource_lifetime` | completed | 3 | 3 | 0 | 0 | 0 | complete |
| `ohscanner.known_disclosed_cves` | completed | 3 | 3 | 0 | 0 | 0 | complete |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:7ad45310eea2370c` | `cJSON.c:1` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |
| `ohscanner.cpp.null_dereference` | `ohscanner.cpp.null_dereference:f4aaa94becf81fee` | `cJSON_Utils.c:1` | `ohcpp-null-dereference-candidate-001` | guard_dominance=unknown; cross_function_alias=unknown; compile_context=missing; entry_or_privilege_boundary=missing; attacker_control=missing; sensitive_operation_reachability=missing; trigger_conditions=missing; cia_impact=missing |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.bounds`: complete, 3/3 applicable files examined; unexamined=0
- `ohscanner.cpp.integer_bounds`: complete, 3/3 applicable files examined; unexamined=0
- `ohscanner.cpp.null_dereference`: partial, 2/3 applicable files examined; unexamined=1
- `ohscanner.cpp.resource_lifetime`: complete, 3/3 applicable files examined; unexamined=0
- `ohscanner.known_disclosed_cves`: complete, 3/3 applicable files examined; unexamined=0

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.cpp.bounds`: Absence of a finding is not a safe verdict; partial/failed source is unknown, not a miss.
- `ohscanner.cpp.bounds`: Candidate only: lexical array/copy facts do not prove exploitability or a product vulnerability.
- `ohscanner.cpp.bounds`: Pointer capacities, aliases, wrappers, interprocedural lengths, macros, template instantiation and full C++ CFG semantics remain unknown unless explicitly modeled.
- `ohscanner.cpp.bounds`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.bounds`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.bounds`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.integer_bounds`: A guarded or unknown expression is not a safe verdict; partial/failed source remains unknown.
- `ohscanner.cpp.integer_bounds`: Candidate only: lexical integer arithmetic does not prove allocation undersizing or product impact.
- `ohscanner.cpp.integer_bounds`: Signedness, promotions, macro constants, overflow intrinsics, templates and interprocedural range facts remain unknown unless explicitly modeled.
- `ohscanner.cpp.integer_bounds`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.integer_bounds`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.integer_bounds`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.null_dereference`: Bounded lexical C/C++ analysis only; CFG/dominance, cross-function alias, macro, template, exception, destructor and build context may remain unknown.
- `ohscanner.cpp.null_dereference`: unknown_reason: cross_function_alias
- `ohscanner.cpp.null_dereference`: unknown_reason: unresolved_function_return_nullability
- `ohscanner.cpp.null_dereference`: unknown_reason: function_return_nullability_unknown
- `ohscanner.cpp.null_dereference`: narrow negative only: no bounded source/sink candidate matched; compile_context and product evidence remain missing; not a safe verdict.
- `ohscanner.cpp.null_dereference`: Zero findings under this bounded rule are not a safe verdict.
- `ohscanner.cpp.null_dereference`: Member bindings are matched only by one lexically enclosing class and qualified member name; cross-class or shadowed identity remains unknown.
- `ohscanner.cpp.null_dereference`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.null_dereference`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.null_dereference`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.null_dereference`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.
- `ohscanner.cpp.null_dereference`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.cpp.resource_lifetime`: Absence of a finding is not a safe verdict; partial/failed source remains unknown.
- `ohscanner.cpp.resource_lifetime`: Branch, label, cross-function ownership, containers, callbacks, exceptions, destructor timing and custom allocators remain unknown; transitions between lexical flow segments are not joined.
- `ohscanner.cpp.resource_lifetime`: Candidate only: local lexical resource state does not prove UAF/double-free exploitability.
- `ohscanner.cpp.resource_lifetime`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.resource_lifetime`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.resource_lifetime`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.known_disclosed_cves`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.known_disclosed_cves`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.known_disclosed_cves`: Diagnostic does not establish vulnerability, reachability or security impact.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `684ffa45381daa419a19962aa14bd0bdfc922bf50dea9d621c173242277ce1b9`
- Language matching plans attempts; actual coverage remains in the results above.
