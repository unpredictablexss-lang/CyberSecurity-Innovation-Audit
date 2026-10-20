# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/miscservices_pasteboard`
- Pinned commit: `dd22c7cb5e5f207a6c38c50f45b7369ee8575840`
- Git tree: `e374a0d61c9ec664ddd29fc17002797828c480ee`
- Snapshot SHA-256: `010bee868a15d363b206b09312efe4e56826d5bb4142afec82524d1659f95ba8`
- Source files indexed: 2
- Parsing coverage: `{"complete": 2}`
- Detector runs: 1
- Total unverified diagnostics: 2
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.known_disclosed_cves` | completed | 2 | 2 | 0 | 0 | 2 | complete |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.known_disclosed_cves` | `ohscanner.known_disclosed_cves:5e7088b7e43b3d9b` | `services/core/src/pasteboard_service.cpp:222` | `ohknowncve-pasteboard-cve-2025-25212` | component_identity=missing; product_build=missing; attacker_path=missing; impact=missing |
| `ohscanner.known_disclosed_cves` | `ohscanner.known_disclosed_cves:24600cb387537484` | `services/zidl/src/pasteboard_service_stub.cpp:41` | `ohknowncve-pasteboard-cve-2025-27247` | component_identity=missing; product_build=missing; attacker_path=missing; impact=missing |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.known_disclosed_cves`: complete, 2/2 applicable files examined; unexamined=0

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.known_disclosed_cves`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.known_disclosed_cves`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.known_disclosed_cves`: Diagnostic does not establish vulnerability, reachability or security impact.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `30092c472e1c09cec839459cfafd39c3dcd5c25a541b7cc08f5a61eb2b9cc403`
- Language matching plans attempts; actual coverage remains in the results above.
