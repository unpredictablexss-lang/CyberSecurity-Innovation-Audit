# OHScanner M2 reviewed-detector execution

> Detection candidates and coverage limitations, NOT validated vulnerabilities.

- Source repository (declared): `openharmony/applications_app_samples`
- Pinned commit: `c60bab52dcaf7341a2c26dc038bd468b4d577e01`
- Git tree: `b1500d3b26544c6d3ecaa51b7d1f96b161255e5c`
- Snapshot SHA-256: `d257c60825aeb0b07202a0073f0a10a194b380204f4e4823363d310790d15b0b`
- Source files indexed: 44
- Parsing coverage: `{"complete": 41, "partial": 3}`
- Detector runs: 11
- Total unverified diagnostics: 0
- Validated vulnerabilities: **0** (no runtime verification performed)

## Per-detector results

| Detector | Execution | Inspected files | Complete | Partial | Not analyzed | Diagnostics | Coverage |
|---|---|---:|---:|---:|---:|---:|---|
| `ohscanner.cpp.bounds` | blocked | 0 | 0 | 0 | 0 | 0 | not_applicable |
| `ohscanner.cpp.integer_bounds` | blocked | 0 | 0 | 0 | 0 | 0 | not_applicable |
| `ohscanner.cpp.lifetime` | blocked | 0 | 0 | 0 | 0 | 0 | not_applicable |
| `ohscanner.cpp.null_dereference` | blocked | 0 | 0 | 0 | 0 | 0 | not_applicable |
| `ohscanner.cpp.resource_lifetime` | blocked | 0 | 0 | 0 | 0 | 0 | not_applicable |
| `ohscanner.cpp.shared_ptr_race` | blocked | 0 | 0 | 0 | 0 | 0 | not_applicable |
| `ohscanner.cpp.unsafe_memory_call` | blocked | 0 | 0 | 0 | 0 | 0 | not_applicable |
| `ohscanner.data.sensitive_exposure` | blocked | 0 | 0 | 0 | 0 | 0 | not_applicable |
| `ohscanner.interface.ipc` | blocked | 0 | 0 | 0 | 0 | 0 | not_applicable |
| `ohscanner.known_disclosed_cves` | blocked | 0 | 0 | 0 | 0 | 0 | not_applicable |
| `ohscanner.oh.arkts_js` | completed | 44 | 41 | 3 | 0 | 0 | partial |

## Candidate evidence and missing proof

| Detector | Candidate ID | File:line | Rule | Unverified proof obligations |
|---|---|---|---|---|
| — | — | — | — | No reported candidate; NOT proof of safety |

## Coverage gaps

Scope counts source inspection, not complete semantic coverage; partial remains unknown.
Files without a claiming detector: 0
- `ohscanner.cpp.bounds`: not_applicable, 0/0 applicable files examined; unexamined=0
- `ohscanner.cpp.integer_bounds`: not_applicable, 0/0 applicable files examined; unexamined=0
- `ohscanner.cpp.lifetime`: not_applicable, 0/0 applicable files examined; unexamined=0
- `ohscanner.cpp.null_dereference`: not_applicable, 0/0 applicable files examined; unexamined=0
- `ohscanner.cpp.resource_lifetime`: not_applicable, 0/0 applicable files examined; unexamined=0
- `ohscanner.cpp.shared_ptr_race`: not_applicable, 0/0 applicable files examined; unexamined=0
- `ohscanner.cpp.unsafe_memory_call`: not_applicable, 0/0 applicable files examined; unexamined=0
- `ohscanner.data.sensitive_exposure`: not_applicable, 0/0 applicable files examined; unexamined=0
- `ohscanner.interface.ipc`: not_applicable, 0/0 applicable files examined; unexamined=0
- `ohscanner.known_disclosed_cves`: not_applicable, 0/0 applicable files examined; unexamined=0
- `ohscanner.oh.arkts_js`: partial, 41/44 applicable files examined; unexamined=3

## Limitations

- Diagnostics are candidates/evidence only, not proof of security impact.
- Zero diagnostics does NOT mean the component is free of vulnerabilities.
- Git origin name is user declared; source is pinned local objects, not an OH product build.
- No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.
- `ohscanner.cpp.bounds`: not_applicable: no source with supported language.
- `ohscanner.cpp.bounds`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.bounds`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.bounds`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.bounds`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.cpp.integer_bounds`: not_applicable: no source with supported language.
- `ohscanner.cpp.integer_bounds`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.integer_bounds`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.integer_bounds`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.integer_bounds`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.cpp.lifetime`: not_applicable: no source with supported language.
- `ohscanner.cpp.lifetime`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.lifetime`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.lifetime`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.lifetime`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.cpp.null_dereference`: not_applicable: no source with supported language.
- `ohscanner.cpp.null_dereference`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.null_dereference`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.null_dereference`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.null_dereference`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.cpp.resource_lifetime`: not_applicable: no source with supported language.
- `ohscanner.cpp.resource_lifetime`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.resource_lifetime`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.resource_lifetime`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.resource_lifetime`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.cpp.shared_ptr_race`: not_applicable: no source with supported language.
- `ohscanner.cpp.shared_ptr_race`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.shared_ptr_race`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.shared_ptr_race`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.shared_ptr_race`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.cpp.unsafe_memory_call`: not_applicable: no source with supported language.
- `ohscanner.cpp.unsafe_memory_call`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.cpp.unsafe_memory_call`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.cpp.unsafe_memory_call`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.cpp.unsafe_memory_call`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.data.sensitive_exposure`: not_applicable: no source with supported language.
- `ohscanner.data.sensitive_exposure`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.data.sensitive_exposure`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.data.sensitive_exposure`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.data.sensitive_exposure`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.interface.ipc`: not_applicable: no source with supported language.
- `ohscanner.interface.ipc`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.interface.ipc`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.interface.ipc`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.interface.ipc`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.known_disclosed_cves`: not_applicable: no source with supported language.
- `ohscanner.known_disclosed_cves`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.known_disclosed_cves`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.known_disclosed_cves`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.known_disclosed_cves`: Coverage incomplete or unsupported; do not infer safety.
- `ohscanner.oh.arkts_js`: ArkTS/JS frontend: 44 file(s) parsed; 41 complete, 3 partial, 0 unsupported; 237 call site(s) recovered.
- `ohscanner.oh.arkts_js`: Public analysis coverage follows both frontends: complete requires a complete shared SourceUnit parse AND a complete private parse. Shared not_run/failed/partial stays partial inspection even when the private grammar recovers a complete tree; the preceding frontend counts describe the private parse only.
- `ohscanner.oh.arkts_js`: ArkTS `struct` and ArkTS decorators are outside the TypeScript grammar; a partial parse is reported for every such file and no component/decorator semantics are claimed from it. Only recovered call/class/property structure is read.
- `ohscanner.oh.arkts_js`: No CFG; taint crosses one same-file function hop at most (function declarations only, not methods or arrow functions). No manifest (module.json5) parsing, installed-package or page-origin facts. Guard detection is a bounded AST branch containment or direct preceding early rejection on the same argument. Reassignment invalidates the structural guard; this is not CFG/alias proof or validation of the predicate policy.
- `ohscanner.oh.arkts_js`: Ability surface: 1 exported Ability/Extension class(es) seen; export/permission state is an obligation, never inferred from the class.
- `ohscanner.oh.arkts_js`: WebView bridge coverage: 0 registration(s), 0 with an origin predicate in the same function.
- `ohscanner.oh.arkts_js`: Taint coverage: 2 path sink(s), 0 behind a same-function path predicate; 0 eval site(s).
- `ohscanner.oh.arkts_js`: N-API binding map: 0 .so module(s) and 0 function signature(s) declared in the scan's .d.ts files; 0 call site(s) into lib*.so imports, 0 unmapped (module or export not declared in this scan), 0 behind a same-function numeric predicate. A declaration is a type statement, not a runtime check.
- `ohscanner.oh.arkts_js`: All output is candidate/unassessed; no candidate is a vulnerability finding and no reachability is established by this frontend.
- `ohscanner.oh.arkts_js`: M1 local Git objects pinned by full commit/tree; repository ownership is user-declared.
- `ohscanner.oh.arkts_js`: Execution is synchronous; hard timeout/memory isolation is not yet implemented.
- `ohscanner.oh.arkts_js`: Diagnostic does not establish vulnerability, reachability or security impact.
- `ohscanner.oh.arkts_js`: INCOMPLETE COVERAGE: detector-internal file outcome is unknown/partial; see coverage sidecar.

## Frozen execution plan

- Planner: 0.1.1; mode: explicit
- Plan SHA-256: `3656e10ca2198349a4ce55325f622981a7d8949d50585d9bd0d001882b059bc6`
- Language matching plans attempts; actual coverage remains in the results above.
