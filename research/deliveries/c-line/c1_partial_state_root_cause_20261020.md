# C1 partial-state root-cause scout — 2026-10-20

## Scope and result

Worktree was clean at start, HEAD `463f6e3b9e180aa1d39fe6eb49079c66de046e31` (runner applicability fix plus saved post-fix replay). No production files were changed in this scout.

Replayed evidence is saved in `c1_post_fix.json/.md`. It binds repository `openharmony/arkcompiler_ets_runtime`, commit `a65a2853ccae13da167d9aa4720ab8b11ec16656`, tree `8781f036a3e7e04d8e0b34970d5f623b42875016`, target Git blob `68fb3b0adc4f9062889a861be51b7be90362e37a`, and target SHA-256 `76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c`.

The run remains `blocked`, with target parse `partial`, 13 raw parser issues, detector analysis `partial`, and zero diagnostics. In this report, `blocked` and zero diagnostics are not safety conclusions.

## The 13 parser diagnostics

`src/parser/ast.py:190-220` parses raw source bytes with Tree-sitter C++ (no macro expansion), then marks any tree-sitter ERROR/MISSING node as a parse issue. The saved CLI environment explicitly reports `macro_expansion: false`.

| Locations | Raw parser symptom | Source cause / control |
|---|---|---|
| 148, 151 (`missing }`), 154 (`ERROR`), 155 (`missing ;`), 166 (`ERROR`) | Cascading errors through an IR control-flow body and function close. | Raw `IR_ELSE` tokens at 147/150/153 are C++ macros. At the exact pinned header `ecmascript/compiler/stub_builder.h:1551-1570`, `IR_IF` expands to a `for`/`if` and `IR_ELSE` to `else if`. Raw DSL minimal control parses partial; an expanded ordinary C++ equivalent parses complete. |
| 2862 (`missing }`), 2873 (`ERROR`) | Same raw IR-else/body-closing cascade. | `} IR_ELSE {` at source line 2861; the pinned `IR_ELSE` macro expansion above explains the parser mismatch. |
| 2952 (`ERROR`), 2953 (`missing }`), 3041 (`ERROR`) | Error inside the `IR_ELSE` arm, cascading to the enclosing function close. | The `Label dblLabels[storeKinds] = { Label(env), ... };` initializer is valid by itself: an equivalent minimal C++ declaration parses complete. It is under `} IR_ELSE {` at 2951, so this is a macro-context/parser cascade, not evidence that the array initializer is unsupported. |
| 3286 (`missing ;`) | The raw macro invocation is parsed like an expression statement. | `BRANCH` at this location omits a source semicolon, but the exact pinned `ecmascript/compiler/circuit_builder.h:283-288` expands `BRANCH(...)` to a compound block `{ ... }`, which is a complete statement without a trailing semicolon. Raw invocation minimal control is partial; its expanded block form is complete. |
| 3611 (`missing ;`), 3629 (`ERROR`) | Raw macro invocation inside `switch` and cascading close. | `BUILTIN_COMPILER_TYPED_ARRAY_TYPES(BUILTIN_COMPILER_TYPED_ARRAY_LABEL)` expands through the exact target header macro at `builtins_typedarray_stub_builder.h:24` into `case` labels and blocks; unexpanded raw macro invocation is not a valid switch statement. An equivalent expanded switch parses complete. |

Diagnostic line groups total 13. The individual Tree-sitter node rows are persisted in `c1_post_fix.json`. The relevant macros were read from the same exact pinned Git commit, not from current working-tree headers.

## Parser limitation versus detector/model unknown

`detector_model_incomplete` is a runner label, not a model-version or binding rejection: `src/ohscanner/runner.py:170-188` maps a per-file `partial` analysis state to that string. The detector does inspect locally recoverable functions under its explicit research-partial path; C1's exact target binding passes, but file coverage remains partial because the raw translation-unit parse is partial and the analysis adds `experimental_partial_function_scope`, `parse_dependency_contamination_unknown`, `partial_scope_routed_through_semantic_selector`, and `unresolved_local_observations`.

The separate `Map` observation at line 2747 is an effect/model unknown, not one of the 13 Tree-sitter locations. Direct `analyze_unit(..., research_partial=True)` on the exact target returns one `unknown` observation with reason `type_fact_invalidated_by_call`, target `new:108922`, type token sampled at line 2721, and effect sites including `JSCallDispatch` at line 2739. The source allocates via `NewTypedArray` at 2713, samples the result's type at 2721, calls user callback dispatch at 2739, and stores with `FastSetPropertyByIndex` at 2747. The callback can execute arbitrary JS; the allocator/species path could also publish the new array. The available facts do not prove non-escape or type stability across that callback, so retaining `unknown` is the sound choice. No candidate is justified by this trace, and no model relaxation is proposed.

## Safe next candidate

The concrete reusable limitation is lack of preprocessing for Ark's source DSL and macro-generated switch cases. A follow-on should prototype an **exact-source, macro-aware parse profile** using the pinned header blobs and an explicitly supplied build/preprocessor configuration, preserve source locations through expansion, and keep status partial/unknown whenever required headers/defines are unavailable. Do not globally rewrite `IR_IF`, `BRANCH`, or arbitrary macro calls as text: those names are context- and definition-dependent. Before production adoption, use minimal raw-versus-expanded controls above plus a broader pinned-source matrix; ensure expansion cannot silently upgrade an unresolved parse to complete.

The Map invalidation could be reconsidered only with a separate escape/effect proof for the exact allocator result and callback path. Until then, it should remain unknown.
