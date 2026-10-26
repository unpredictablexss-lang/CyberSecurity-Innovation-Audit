# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `fixture/disclosed-cves`
- Pinned commit: `aaa265e33b497a26a638a2d79a68b3b8e0663e12`
- Git tree: `13964f373191a228bbb993eb988085d1ed11055d`
- Snapshot SHA-256: `2cbc929266810cfc4b94291bce2c184691f3d05577484ba5064eb162ce5f65d8`
- Source files indexed: 3
- Parsing coverage: `{"complete": 2, "partial": 1}`
- Detector runs: 4
- Total unverified diagnostics: 3
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.bounds` | blocked | 2 | 0 | 2 | 1 | 0 | partial |
| `ohscanner.cpp.integer_bounds` | blocked | 3 | 0 | 3 | 0 | 0 | partial |
| `ohscanner.cpp.resource_lifetime` | blocked | 2 | 0 | 2 | 1 | 0 | partial |
| `ohscanner.known_disclosed_cves` | blocked | 3 | 0 | 3 | 0 | 3 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.known_disclosed_cves` | `ohscanner.known_disclosed_cves:20ca788d7308dbc9` | `cJSON.c:1` | `ohknowncve-cjson-cve-2026-67216` | component_identity=missing; product_build=missing; attacker_path=missing; impact=missing |
| `ohscanner.known_disclosed_cves` | `ohscanner.known_disclosed_cves:1cd06425d5678440` | `cJSON_Utils.c:1` | `ohknowncve-cjson-cve-2026-67215` | component_identity=missing; product_build=missing; attacker_path=missing; impact=missing |
| `ohscanner.known_disclosed_cves` | `ohscanner.known_disclosed_cves:6108aa06d49cf9b0` | `png.c:1` | `ohknowncve-libpng-cve-2026-46675` | component_identity=missing; product_build=missing; attacker_path=missing; impact=missing |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.bounds`: partial, 0/3 applicable files examined; unexamined=3
- `ohscanner.cpp.integer_bounds`: partial, 0/3 applicable files examined; unexamined=3
- `ohscanner.cpp.resource_lifetime`: partial, 0/3 applicable files examined; unexamined=3
- `ohscanner.known_disclosed_cves`: partial, 0/3 applicable files examined; unexamined=3

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.cpp.bounds`: Absence of a finding is not a safe verdict; partial/failed source is unknown, not a miss.
- `ohscanner.cpp.bounds`: Candidate only: lexical array/copy facts do not prove exploitability or a product vulnerability.
- `ohscanner.cpp.bounds`: Pointer capacities, aliases, wrappers, interprocedural lengths, macros, template instantiation and full C++ CFG semantics remain unknown unless explicitly modeled.
- `ohscanner.cpp.bounds`: cJSON.c: parse_status=partial; bounds coverage remains unknown.
- `ohscanner.cpp.bounds`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.bounds`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.bounds`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.bounds`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.cpp.bounds`: INCOMPLETE COVERAGE: inspected source includes partial/unknown analysis; no safety inference.
- `ohscanner.cpp.integer_bounds`: A guarded or unknown expression is not a safe verdict; partial/failed source remains unknown.
- `ohscanner.cpp.integer_bounds`: Candidate only: lexical integer arithmetic does not prove allocation undersizing or product impact.
- `ohscanner.cpp.integer_bounds`: Signedness, promotions, macro constants, overflow intrinsics, templates and interprocedural range facts remain unknown unless explicitly modeled.
- `ohscanner.cpp.integer_bounds`: cJSON.c: parser reported partial syntax; only the bounded unsigned pointer-offset shape was inspected.
- `ohscanner.cpp.integer_bounds`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.integer_bounds`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.integer_bounds`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.integer_bounds`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.cpp.integer_bounds`: INCOMPLETE COVERAGE: inspected source includes partial/unknown analysis; no safety inference.
- `ohscanner.cpp.resource_lifetime`: Absence of a finding is not a safe verdict; partial/failed source remains unknown.
- `ohscanner.cpp.resource_lifetime`: Branch, label, cross-function ownership, containers, callbacks, exceptions, destructor timing and custom allocators remain unknown; transitions between lexical flow segments are not joined.
- `ohscanner.cpp.resource_lifetime`: Candidate only: local lexical resource state does not prove UAF/double-free exploitability.
- `ohscanner.cpp.resource_lifetime`: cJSON.c: parse_status=partial; resource lifetime remains unknown.
- `ohscanner.cpp.resource_lifetime`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.resource_lifetime`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.resource_lifetime`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.resource_lifetime`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.cpp.resource_lifetime`: INCOMPLETE COVERAGE: inspected source includes partial/unknown analysis; no safety inference.
- `ohscanner.known_disclosed_cves`: cJSON.c: parse_status=partial; lexical matches are retained but remaining coverage is unknown.
- `ohscanner.known_disclosed_cves`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.known_disclosed_cves`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.known_disclosed_cves`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.known_disclosed_cves`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.known_disclosed_cves`: INCOMPLETE COVERAGE: inspected source includes partial/unknown analysis; no safety inference.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `ff3090f517674867c22135b40bac650222ff8b913fe1747aea960b3c69719d34`
- Language matching plans attempts; actual coverage remains in the results above.
