# C1 Map adapter function-scope gate: no-go (2026-10-20)

## Decision

Do not change production adapter admission for this slice. The exact pinned `runtime_stubs.cpp` is file-partial (seven Tree-sitter issues), while the raw source region that appears to implement `GetTypedArrayPropertyByIndex` is locally parse-clean. That alone is not a sufficient function-scoped semantic completeness proof: Tree-sitter sees the declaration as a function whose declarator is `DEF_RUNTIME_STUBS`, so the target function name and signature are supplied by preprocessor semantics that the current `light-ast` pipeline does not materialize. The strict adapter must continue to leave the C1 source-width candidate unknown/no-finding.

This is a parser/evidence limitation, not a safe result and not evidence against the source-level candidate. No runtime or product claim is made.

## Exact source observations

At Ark Runtime commit `a65a2853ccae13da167d9aa4720ab8b11ec16656`, `ecmascript/stubs/runtime_stubs.cpp` is bound to Git blob `14dc06350881b1fa0fdabeeb8465ae9063224d6c` and SHA-256 `0c390fb329387ff75943089da0e7eecab4bc1df21da1be4f33db969b2bf79a46`.

Raw Tree-sitter C++ parsing reports these seven issues (byte offsets are half-open; missing nodes have zero-width spans):

- `ERROR` `[214430,214437)` at source line 4738: `#ifndef`
- `ERROR` `[214513,214519)` at source line 4740: `#endif`
- missing `;` at `[219396,219396)` (line 4891)
- missing `;` at `[243513,243513)`, `[243570,243570)`, `[243623,243623)`, and `[243680,243680)` (lines 5417–5420)

The region `[148861,149326)` (source lines 3169–3176) has a `function_definition` node with `has_error=False`. Its exact text starts `DEF_RUNTIME_STUBS(GetTypedArrayPropertyByIndex)` and its body forwards `argv` slots 0/1/2 as `obj`, `idx`, and `jsType` into `JSTypedArray::FastGetPropertyByIndex`. All seven parser issues are disjoint from this node. The enclosing translation unit remains partial.

The same pinned source defines `DEF_RUNTIME_STUBS(name)` at lines 83–84 and `RUNTIME_STUBS_HEADER(name)` at lines 86–90. The former expands to a `RuntimeStubs::name(uintptr_t argGlue, uint32_t argc, uintptr_t argv)` declaration. The latter invokes `RUNTIME_TRACE` and constructs an `EcmaHandleScope`. Because the raw parser does not expand these macros, its clean body node is not by itself a proof of the expanded declaration or its complete control/effect context.

## Why the scoped exception is not implemented

The existing C1 species-read-width profile pins six helper files, including `runtime_stubs.cpp`, but does not pin the complete macro/declaration chain needed to connect the macro-shaped function to the runtime-call identity. Independent inspection identified additional exact-source inputs: `runtime_stub_list.h` (blob `b570a0b2a016fd808e005eb23e16f80896d0c6fd`, SHA-256 `fcf0b1daa2660dbbae359ea5a88ee0743d69db994539fc11342e05b394b08e22`), `rt_call_signature.h` (blob `fc778d25c2fd5266ecb756a820544c2b01bb0f1f`, SHA-256 `74c0769d7d1d26e112351656e872318e49372f817118715368c13e837af80435`), `runtime_stubs.h` (blob `2aabf8d8691465db5998a823f46a3b11ef10da88`, SHA-256 `f82a61228dfe7777ecbccfd98f6ed9f914a024112f93b25940bb1031f14b1f7b`), and `js_typed_array.h` (blob `d59bc3138542afa22bfe2a2f42f5fa756a6dae1a`, SHA-256 `a22084f1746bbfe86656a92d4847bebfab3057e667b25bcb0853cc648c29e669`). The runtime header declares members through list macros; `RTSTUB_ID` maps a symbolic name into `RuntimeStubCSigns::ID_name`; the typed-array header declares the callee. These facts are not yet part of the current species-read-width dependency set.

Even with those files added, a future narrow admission needs a source-bound check that validates the exact macro invocation and expansion-relevant definitions, call-site/runtime-stub identity, callee declaration, and the parse-error interval separation. It must fail closed if any relevant macro or required declaration is absent, changed, conditionally ambiguous, or outside the pinned evidence set. `RUNTIME_TRACE` and the exact preprocessing/build profile are not resolved by the present `light-ast` evidence. Merely matching the function name, blob, or byte span would be insufficient. No global complete-AST waiver or `_dependency_error` relaxation is justified.

## Reproduction and controls

The exact pinned source was read from the local Git object store and parsed using the same Tree-sitter C++ grammar as `src/ohscanner/detectors/ark_runtime/syntax.py`. The parser produced the seven issue spans above and the local function node described above. This was a read-only audit; no production code or task-tree files were changed. The existing adapter behavior remains fail-closed because `_dependency_error` requires complete dependency ASTs. The target remains partial/limited, and the bound direct analyzer's candidate does not become an integrated adapter finding.

A later implementation can be considered when the full function identity, macro expansion context and runtime-call dispatch/declaration evidence are all pinned and regression-tested for positive exact profile, errors outside/inside the target function, missing or mutated helpers, stale blob facts, wrong revision, unrelated function, and generic/unbound controls.
