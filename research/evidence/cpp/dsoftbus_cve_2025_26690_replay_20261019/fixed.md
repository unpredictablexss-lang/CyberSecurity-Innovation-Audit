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
| `ohscanner.cpp.null_dereference` | completed | 1 | 1 | 0 | 0 | 0 | complete |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| — | — | — | — | No reported candidate; NOT proof of safety |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.null_dereference`: complete, 1/1 applicable files examined; unexamined=0

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.cpp.null_dereference`: Bounded lexical C/C++ analysis only; CFG/dominance, cross-function alias, macro, template, exception, destructor and build context may remain unknown.
- `ohscanner.cpp.null_dereference`: narrow negative only: no bounded source/sink candidate matched; compile_context and product evidence remain missing; not a safe verdict.
- `ohscanner.cpp.null_dereference`: Zero findings under this bounded rule are not a safe verdict.
- `ohscanner.cpp.null_dereference`: Member bindings are matched only by one lexically enclosing class and qualified member name; cross-class or shadowed identity remains unknown.
- `ohscanner.cpp.null_dereference`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.null_dereference`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.null_dereference`: Diagnostic does not establish vulnerability, reachability or security impact.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `8734e8bde72718e2a14d665b7231a50188b1aae3741c9accfeed8960d5bca4bf`
- Language matching plans attempts; actual coverage remains in the results above.
