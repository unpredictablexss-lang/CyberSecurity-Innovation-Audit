# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/communication_dsoftbus`
- Pinned commit: `192f3e11d74beeaa3d879333471deb8a24a7e1c5`
- Git tree: `1d58ba0ef706a6f69dd372bd496c8058810882aa`
- Snapshot SHA-256: `c8867f500a082ea923b8aede2735e12d409149f8071900098ee3f96f55e8bf11`
- Source files indexed: 1
- Parsing coverage: `{"complete": 1}`
- Detector runs: 1
- Total unverified diagnostics: 0
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.null_dereference` | blocked | 1 | 0 | 1 | 0 | 0 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| — | — | — | — | No reported candidate; NOT proof of safety |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.null_dereference`: partial, 0/1 applicable files examined; unexamined=1

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.cpp.null_dereference`: Bounded lexical C/C++ analysis only; CFG/dominance, cross-function alias, macro, template, exception, destructor and build context may remain unknown.
- `ohscanner.cpp.null_dereference`: unknown_reason: guard_dominance_unknown_without_compile_context
- `ohscanner.cpp.null_dereference`: Zero findings under this bounded rule are not a safe verdict.
- `ohscanner.cpp.null_dereference`: Member bindings are matched only by one lexically enclosing class and qualified member name; cross-class or shadowed identity remains unknown.
- `ohscanner.cpp.null_dereference`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.null_dereference`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.null_dereference`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.null_dereference`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.
- `ohscanner.cpp.null_dereference`: Coverage incomplete or unsupported; do not infer safety.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `425ff83fdb694b99269b07b6ae3a3cdff5b231c81d51cb7cd677b7d2e1238817`
- Language matching plans attempts; actual coverage remains in the results above.

