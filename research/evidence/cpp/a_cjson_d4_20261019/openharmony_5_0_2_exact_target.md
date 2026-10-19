# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/third_party_cJSON`
- Pinned commit: `237476eb18e47fafac854d1a42b1f3e04cb1a8f6`
- Git tree: `273988672a8981471ebad5ad532f119aef5bdb8c`
- Snapshot SHA-256: `ccae6ee023a2ad7769970c52ee72698fe4cb01679458a410a91329bf36ca51f8`
- Source files indexed: 2
- Parsing coverage: `{"complete": 1, "partial": 1}`
- Detector runs: 1
- Total unverified diagnostics: 3
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.known_disclosed_cves` | blocked | 2 | 0 | 2 | 0 | 3 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.known_disclosed_cves` | `ohscanner.known_disclosed_cves:9a3eff282f8d2e2d` | `cJSON.c:3310` | `ohknowncve-cjson-cve-2026-67216` | component_identity=missing; product_build=missing; attacker_path=missing; impact=missing |
| `ohscanner.known_disclosed_cves` | `ohscanner.known_disclosed_cves:efcd3075d2f20c00` | `cJSON_Utils.c:285` | `ohknowncve-cjson-cve-2025-57052` | component_identity=missing; product_build=missing; attacker_path=missing; impact=missing |
| `ohscanner.known_disclosed_cves` | `ohscanner.known_disclosed_cves:ecc62a612c003884` | `cJSON_Utils.c:825` | `ohknowncve-cjson-cve-2026-67215` | component_identity=missing; product_build=missing; attacker_path=missing; impact=missing |

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
- Plan SHA-256: `251a11ef34e6ddee09d5547054ebfcc59f476e00a0ed5095aa4473225fcd361b`
- Language matching plans attempts; actual coverage remains in the results above.
