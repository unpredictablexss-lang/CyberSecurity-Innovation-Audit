# C1 Map adapter independent fail-closed replay (2026-10-20)

## Scope and result

Independent test of C-TEST-C1-MAP-ADAPTER-20261020 on analyzer checkout `874edb47a89d542be682fe3de6c4df7020caa180`. The requested starting SHA `fc8b03905cce1accfc9e7e810a7c604328d669fe` was present in history; `git diff fc8b039..HEAD -- src/ohscanner/detectors/ark_runtime` was empty, so production code under test was unchanged from that base. I did not edit production code or the task tree.

Exact C1 target `a65a2853ccae13da167d9aa4720ab8b11ec16656` plus its six source-bound helper inputs produced adapter status `blocked`, target outcome `partial`, and zero findings. Limitation: `species read-width source evidence is incomplete or mismatched; retaining unknown helper effects`. The helper evidence is incomplete because `runtime_stubs.cpp` is partial (7 parse issues) and the existing adapter requires dependency parse status `complete`. This confirms fail-closed behavior, not safety and not a negative security verdict.

## Parser audit

At the pinned commit, `ecmascript/stubs/runtime_stubs.cpp` is blob `14dc06350881b1fa0fdabeeb8465ae9063224d6c`, SHA-256 `0c390fb329387ff75943089da0e7eecab4bc1df21da1be4f33db969b2bf79a46`. Tree-sitter C++ reports seven issues, all outside the macro-shaped source region `[148861,149326)`:

| Kind | Half-open byte span | Source line | Text / detail |
|---|---:|---:|---|
| ERROR | `[214430,214437)` | 4738 | `#ifndef` |
| ERROR | `[214513,214519)` | 4740 | `#endif` |
| missing `;` | `[219396,219396)` | 4891 | zero-width missing node |
| missing `;` | `[243513,243513)` | 5417 | zero-width missing node |
| missing `;` | `[243570,243570)` | 5418 | zero-width missing node |
| missing `;` | `[243623,243623)` | 5419 | zero-width missing node |
| missing `;` | `[243680,243680)` | 5420 | zero-width missing node |

The candidate region at lines 3170–3177 is a locally error-free `function_definition`, but its declarator is the literal `DEF_RUNTIME_STUBS`; the parser does not resolve it as `GetTypedArrayPropertyByIndex`. The source macro at lines 83–84 expands to `JSTaggedType RuntimeStubs::name(uintptr_t argGlue, uint32_t argc, uintptr_t argv)`. The body forwards arguments 0, 1 and 2 to `JSTypedArray::FastGetPropertyByIndex`. An injected syntax error (`JSTaggedValue obj = ;`) generated an ERROR span inside this node `[148989,148990)`; the existing errors and a parser-control error elsewhere were outside it. These byte-range controls show local syntax separation only. They do not establish expanded declaration identity, preprocessing context or semantic completeness.

Relevant exact same-commit inputs inspected:

- `runtime_stubs.cpp`: blob `14dc06350881b1fa0fdabeeb8465ae9063224d6c`, SHA-256 `0c390fb329387ff75943089da0e7eecab4bc1df21da1be4f33db969b2bf79a46`; defines `DEF_RUNTIME_STUBS` and `RUNTIME_STUBS_HEADER`; the latter calls `RUNTIME_TRACE` and creates `EcmaHandleScope`.
- `runtime_stub_list.h`: blob `b570a0b2a016fd808e005eb23e16f80896d0c6fd`, SHA-256 `fcf0b1daa2660dbbae359ea5a88ee0743d69db994539fc11342e05b394b08e22`; contains `GetTypedArrayPropertyByIndex` in a generated stub list (line 554), which feeds declaration/ID lists.
- `runtime_stubs.h`: blob `2aabf8d8691465db5998a823f46a3b11ef10da88`, SHA-256 `f82a61228dfe7777ecbccfd98f6ed9f914a024112f93b25940bb1031f14b1f7b`; declares members through `RUNTIME_STUB_WITH_GC_LIST`.
- `rt_call_signature.h`: blob `fc778d25c2fd5266ecb756a820544c2b01bb0f1f`, SHA-256 `74c0769d7d1d26e112351656e872318e49372f817118715368c13e837af80435`; generates runtime IDs from stub lists and defines `RTSTUB_ID(name)` as `RuntimeStubCSigns::ID_##name`.
- `runtime_call_id.h`: blob `ba92f22f266203c59ffa29fa0c595e8e4c45b311`, SHA-256 `328b9618e500d02222600e9e80abb3bff235bcdc186bc4c7a9d4180d6ff8d36d`; defines `RUNTIME_TRACE` in multiple preprocessor branches.
- `js_typed_array.h`: blob `d59bc3138542afa22bfe2a2f42f5fa756a6dae1a`, SHA-256 `a22084f1746bbfe86656a92d4847bebfab3057e667b25bcb0853cc648c29e669`; declares `JSTypedArray::FastGetPropertyByIndex`.
- `rt_call_signature.cpp`: blob `fcf0e0e98ac5235875b7c3e41e3b089acfb1f3c1`, SHA-256 `ec7c0bfb88ac64a648f2b9be873184617e488f183701dd1426b2116d08fdb825`; runtime call-signature registrations consume generated lists.

These inputs make a future bounded check plausible, but pinning them alone is not enough. The exact preprocessing flags selecting `RUNTIME_TRACE` and runtime-stub list branches remain unknown; the actual compiled call/registration dispatch path and macro expansion are not established by `light-ast`. A safe positive gate would need to validate the exact definitions/invocation, relevant conditional branch or a faithfully expanded parse, call-site/ID/registration relation, callee declaration, and error interval separation. Until then the no-go is supported.

## Adapter control replay

Commands used: a Python heredoc loaded each exact file with `git show <C1>:<path>` from `D:\openHarmonyScanner\tmp\c-line-ark-history-full-snapshots-20261018.git`, created `SourceUnit`s with `src.parser.ast.parse_source`, computed Git blob OIDs from `blob <length>\0<bytes>`, built `ScanContext` (`repository=openharmony/arkcompiler_ets_runtime`, `commit=a65a2853ccae13da167d9aa4720ab8b11ec16656`, `provenance=git_object`, `profile_id=light-ast`), then called `ArkRuntimeTypeSafetyDetector(model=...).detect(ctx, (target,))`.

| Case | Outcome | Findings | Target state |
|---|---|---:|---|
| Exact target + all six exact helper inputs | `blocked`, target `partial` | 0 | `partial` |
| Missing `runtime_stubs.cpp` | `blocked`, target `partial` | 0 | `partial` |
| Appended mutation to `runtime_stubs.cpp` with recomputed source/OID facts | `blocked`, target `partial` | 0 | `partial` |
| Exact bytes with stale `source_blob_oid` for `runtime_stubs.cpp` | `blocked`, target `partial` | 0 | `partial` |
| Wrong request commit | `blocked`, target `not_analyzed` | 0 | `partial` |
| Default `RuntimeTypeModel()` | `blocked`, target `not_analyzed` | 0 | `partial` (default model has an older dependency pin) |
| Exact target model with C1 species/target bindings removed | `blocked`, target `partial` | 0 | `partial` |
| Unrelated `ecmascript/unrelated.cpp` function | `blocked`, `not_analyzed` | 0 | unrelated unit `complete` |

Raw parser controls: baseline target helper region had no intersecting parse issue; an injected syntax error intersected the region; observed baseline translation-unit issues were all disjoint. I did not run a positive adapter-activation case because the strict adapter correctly rejected the only current exact profile, and no function-scoped semantic gate exists in the tested production code. Thus “positive exact profile candidate” and any product/runtime behavior remain unverified.

No vulnerability, runtime, product, safety, or accuracy conclusion is made.
