# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/third_party_cJSON`
- Pinned commit: `5f425f805d567e964e42d7202744f273ab53ace7`
- Git tree: `114b5f44d80d8bffe763efd6bab3fc4bcb5a2cf0`
- Snapshot SHA-256: `84452a40925b94a82d038150157e5a3514289d21ea9562bc58d1e202b98b537e`
- Source files indexed: 2
- Parsing coverage: `{"complete": 1, "partial": 1}`
- Detector runs: 1
- Total unverified diagnostics: 2
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.known_disclosed_cves` | blocked | 2 | 0 | 2 | 0 | 2 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.known_disclosed_cves` | `ohscanner.known_disclosed_cves:7579008a3454ab24` | `cJSON.c:3067` | `ohknowncve-cjson-cve-2026-67216` | component_identity=missing; product_build=missing; attacker_path=missing; impact=missing |
| `ohscanner.known_disclosed_cves` | `ohscanner.known_disclosed_cves:9326978c4040e34b` | `cJSON_Utils.c:808` | `ohknowncve-cjson-cve-2026-67215` | component_identity=missing; product_build=missing; attacker_path=missing; impact=missing |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.known_disclosed_cves`: partial, 0/2 applicable files examined; unexamined=2

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.known_disclosed_cves`: cJSON.c: parse_status=partial; lexical matches are retained but remaining coverage is unknown.
- `ohscanner.known_disclosed_cves`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.known_disclosed_cves`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.known_disclosed_cves`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.known_disclosed_cves`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.known_disclosed_cves`: INCOMPLETE COVERAGE: inspected source includes partial/unknown analysis; no safety inference.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `782059231134745a82d3e72927d66d0bdf4e5ccf7c8fc0101aac868b4062834c`
- Language matching plans attempts; actual coverage remains in the results above.
