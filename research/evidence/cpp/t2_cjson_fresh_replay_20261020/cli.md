# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/third_party_cJSON`
- Pinned commit: `0c2c9dff82cc85539c8362132d7a5f6bf7d1e748`
- Git tree: `0d8e50cc18f9ae178e9969eed40f8a0c94fb3856`
- Snapshot SHA-256: `84452a40925b94a82d038150157e5a3514289d21ea9562bc58d1e202b98b537e`
- Source files indexed: 2
- Parsing coverage: `{"complete": 1, "partial": 1}`
- Detector runs: 1
- Total unverified diagnostics: 3
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.resource_lifetime` | blocked | 2 | 0 | 2 | 0 | 3 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:0618f035f65bb977` | `cJSON.c:3161` | `ohcpp-resource-exhaustion-recursive-compare-cost-candidate-005` | recursive_compare_shape=unknown; lookup_cost=unknown; input_shape=missing; trigger_conditions=missing |
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:ec13a027e473cfd1` | `cJSON_Utils.c:932` | `ohcpp-resource-exhaustion-tree-amplification-candidate-004` | recursive_destructor_binding=unknown; tree_amplification=unknown; attacker_control=missing; trigger_conditions=missing |
| `ohscanner.cpp.resource_lifetime` | `ohscanner.cpp.resource_lifetime:f40aaf078acb34e8` | `cJSON_Utils.c:950` | `ohcpp-resource-exhaustion-tree-amplification-candidate-004` | recursive_destructor_binding=unknown; tree_amplification=unknown; attacker_control=missing; trigger_conditions=missing |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.resource_lifetime`: partial, 0/2 applicable files examined; unexamined=2

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.cpp.resource_lifetime`: Absence of a finding is not a safe verdict; partial/failed source remains unknown.
- `ohscanner.cpp.resource_lifetime`: Branch, label, cross-function ownership, containers, callbacks, exceptions, destructor timing and custom allocators remain unknown; transitions between lexical flow segments are not joined.
- `ohscanner.cpp.resource_lifetime`: Candidate only: local lexical resource state does not prove UAF/double-free exploitability.
- `ohscanner.cpp.resource_lifetime`: cJSON.c: parse_status=partial; only bounded local complexity patterns are retained, semantic coverage remains unknown.
- `ohscanner.cpp.resource_lifetime`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.resource_lifetime`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.resource_lifetime`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.resource_lifetime`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.cpp.resource_lifetime`: INCOMPLETE COVERAGE: inspected source includes partial/unknown analysis; no safety inference.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `29d7efeb8f030fe8429cc8bde39e330a70cd49583f7e7ccc8230e6247b247829`
- Language matching plans attempts; actual coverage remains in the results above.
