# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/miscservices_pasteboard`
- Pinned commit: `dd22c7cb5e5f207a6c38c50f45b7369ee8575840`
- Git tree: `e374a0d61c9ec664ddd29fc17002797828c480ee`
- Snapshot SHA-256: `b1a29ee4fbd60595395d4757efe9a998caf9a262adc296f80a0ee4003ba95648`
- Source files indexed: 68
- Parsing coverage: `{"complete": 59, "not_run": 1, "partial": 8}`
- Detector runs: 1
- Total unverified diagnostics: 2
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.known_disclosed_cves` | blocked | 67 | 0 | 67 | 0 | 2 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| `ohscanner.known_disclosed_cves` | `ohscanner.known_disclosed_cves:fc93dad6ce585acb` | `services/core/src/pasteboard_service.cpp:241` | `ohknowncve-pasteboard-cve-2025-25212` | component_identity=missing; product_build=missing; attacker_path=missing; impact=missing |
| `ohscanner.known_disclosed_cves` | `ohscanner.known_disclosed_cves:a18878f42bf7e7af` | `services/zidl/src/pasteboard_service_stub.cpp:41` | `ohknowncve-pasteboard-cve-2025-27247` | component_identity=missing; product_build=missing; attacker_path=missing; impact=missing; permission_guard=unknown; permission_guard_observation=unknown |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 1
- `interfaces/declaration/api/@ohos.pasteboard.d.ts`
- `ohscanner.known_disclosed_cves`: partial, 0/67 applicable files examined; unexamined=67

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- Some indexed source files have no claiming detector; their security analysis is unknown.
- `ohscanner.known_disclosed_cves`: interfaces/kits/napi/src/napi_init.cpp: parse_status=partial; lexical matches are retained but remaining coverage is unknown.
- `ohscanner.known_disclosed_cves`: services/core/include/i_pasteboard_observer.h: parse_status=partial; lexical matches are retained but remaining coverage is unknown.
- `ohscanner.known_disclosed_cves`: services/core/include/i_pasteboard_service.h: parse_status=partial; lexical matches are retained but remaining coverage is unknown.
- `ohscanner.known_disclosed_cves`: services/core/include/pasteboard_service.h: parse_status=partial; lexical matches are retained but remaining coverage is unknown.
- `ohscanner.known_disclosed_cves`: services/core/src/pasteboard_storage.cpp: parse_status=partial; lexical matches are retained but remaining coverage is unknown.
- `ohscanner.known_disclosed_cves`: services/test/unittest/src/paste_service_test.cpp: parse_status=partial; lexical matches are retained but remaining coverage is unknown.
- `ohscanner.known_disclosed_cves`: services/zidl/include/pasteboard_observer_stub.h: parse_status=partial; lexical matches are retained but remaining coverage is unknown.
- `ohscanner.known_disclosed_cves`: services/zidl/include/pasteboard_service_stub.h: parse_status=partial; lexical matches are retained but remaining coverage is unknown.
- `ohscanner.known_disclosed_cves`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.known_disclosed_cves`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.known_disclosed_cves`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.known_disclosed_cves`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.known_disclosed_cves`: INCOMPLETE COVERAGE: inspected source includes partial/unknown analysis; no safety inference.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `a6f6991f5a867026961b55c4ad8d0562a5adc2a3c3f5d791c27d7668227b2149`
- Language matching plans attempts; actual coverage remains in the results above.
