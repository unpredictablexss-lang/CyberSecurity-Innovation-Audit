# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `fixture/disclosed-cves`
- Pinned commit: `fb1309f75f13affdf8ca5c93ab88ba87704e4e49`
- Git tree: `736021ede126beffc4b65a364adda8004f1b28c7`
- Snapshot SHA-256: `9debf7abd39fa333d24025da7443f8b8f8fe576acecff15b05906db8fef0f7fc`
- Source files indexed: 3
- Parsing coverage: `{"complete": 3}`
- Detector runs: 1
- Total unverified diagnostics: 0
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.known_disclosed_cves` | completed | 3 | 3 | 0 | 0 | 0 | complete |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| — | — | — | — | No reported candidate; NOT proof of safety |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.known_disclosed_cves`: complete, 3/3 applicable files examined; unexamined=0

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
- Plan SHA-256: `4e27f0ba4e67925b5ee81db75bf57fd6accd4c94303a70a11263cf17b3a322f8`
- Language matching plans attempts; actual coverage remains in the results above.
