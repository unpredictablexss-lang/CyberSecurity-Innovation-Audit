# Independent C1 parser and Map unknown controls — 2026-10-20

## Checkout and source identity

Test worktree was clean at start, HEAD `ea27fa0efe9562d16663b81f4c1d7d03ce8fd90c`. No production files were changed. All source checks used the local bare Git store `D:\openHarmonyScanner\tmp\c-line-ark-history-full-snapshots-20261018.git`; no source retrieval was needed.

The target and relevant macro headers are all read at C1 commit `a65a2853ccae13da167d9aa4720ab8b11ec16656`, tree `8781f036a3e7e04d8e0b34970d5f623b42875016`. `git rev-parse <commit>:<path>` and SHA-256 of `git show <commit>:<path>` yielded:

| Path | Git blob | SHA-256 |
|---|---|---|
| `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp` | `68fb3b0adc4f9062889a861be51b7be90362e37a` | `76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c` |
| `ecmascript/compiler/stub_builder.h` | `9e2fbd3ede1da91133dcd936018285e597944515` | `a11ca83c0a8bbe16ea4ce9dabb2ab3aca2ee9c680a95433371e79494e2a92cb0` |
| `ecmascript/compiler/circuit_builder.h` | `df296de399f31a97417ed124f4ed8f8e4fd608b7` | `41ce63da35d4f9abf5e32bcd417384fadcb018718d002b798e339da11a1a7d70` |
| `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.h` | `017286724e4cd6df1a369589293efe920660c4c6` | `f5b25eed46bfe6e951c6ad8b79ff76bfee8d402868839d21e6d41cd84ef3f8e3` |

Thus the inspected definitions and C1 target are pinned to one source commit, rather than mixed from the checkout's current header files. At those bound headers, `IR_IF` expands through `IR_IF_IMPL` to a `for`/`if`, `IR_ELSE` expands to `else if`, and `BRANCH` expands to a compound block. The bound typed-array header defines `BUILTIN_COMPILER_TYPED_ARRAY_TYPES(V)` as a list of `V(...)` invocations; the target `.cpp` defines `BUILTIN_COMPILER_TYPED_ARRAY_LABEL` and invokes the case-list macro inside `switch`.

## Minimal parser controls

Controls used `src.parser.ast.parse_source(text, "cpp")` from this worktree's tree-sitter parser. For each pair, raw means the macro call remains unexpanded; expanded means its equivalent ordinary C++ syntax is supplied as source. Exact Python control strings:

```python
controls = {
    "raw_ir": "void f(bool c) { IR_IF (c) { first(); } IR_ELSE { second(); } }",
    "expanded_ir": "void f(bool c) { for (IfElseHelper h(c); !h.IsDone(); h.Advance()) if (h.IsTrueBranch()) { first(); } else if (h.IsFalseBranch()) { second(); } }",
    "raw_branch": "void f() { BRANCH(condition, &yes, &no) }",
    "defined_unexpanded_branch": "#define BRANCH(condition, trueLabel, falseLabel) { Branch(condition, trueLabel, falseLabel); }\\nvoid f() { BRANCH(condition, &yes, &no) }",
    "expanded_branch": "void f() { { Branch(condition, &yes, &no); } }",
    "raw_case_list": "void f(int arrayType) { switch (arrayType) { BUILTIN_COMPILER_TYPED_ARRAY_TYPES(BUILTIN_COMPILER_TYPED_ARRAY_LABEL) default: break; } }",
    "expanded_case_list": "void f(int arrayType) { switch (arrayType) { case DataViewType::INT8: { work(); break; } case DataViewType::UINT8: { work(); break; } default: break; } }",
    "standalone_label_array": "void f(int storeKinds, Environment *env) { Label dblLabels[storeKinds] = { Label(env), Label(env), Label(env), Label(env), Label(env), Label(env), Label(env), Label(env), Label(env), Label(env), Label(env) }; }",
}
```

Observed `parse_status` and issue counts:

| Control | Result |
|---|---|
| raw IR_IF/IR_ELSE | `partial`, error + missing |
| expanded IR equivalent | `complete`, no issues |
| raw BRANCH invocation | `partial`, missing |
| BRANCH macro definition present but invocation unexpanded | `partial`, missing |
| expanded BRANCH compound block | `complete`, no issues |
| raw typed-array case-list invocation | `partial`, missing |
| expanded ordinary case labels | `complete`, no issues |
| standalone Label array initializer | `complete`, no issues |

The exact-bound C1 raw source still reports the same 13 issue rows: `missing` at 148, 151, 155, 2862, 2953, 3286, 3611; `error` at 154, 166, 2873, 2952, 3041, 3629. These minimal pairs support classifying the reported sites as expected raw-source macro/preprocessor limitations and cascades, rather than evidence of a standalone `Label` initializer grammar defect. This does not establish that a preprocessor-aware parser would be complete or sound for all build configurations; the currently observed parser reads raw source without macro expansion. No production parser conclusion beyond these controls is claimed.

## Map line 2747 effect unknown

I ran `analyze_unit` with `RuntimeTypeModel()` and `research_partial=True` on the exact bound target `SourceUnit`, preserving its partial parse status. It returned file outcome `partial`; observation at Map line 2747 was `kind=unknown`, reason `type_fact_invalidated_by_call`, with creation at line 2713, sampled type token at line 2721, and effect site `callBuilder.JSCallDispatch` at line 2739. The call site is included in the observation's effect-sites list, followed by the later `FastSetPropertyByIndex` observation point. This reproduces the uncertainty around the callback's potential effects; it does not prove the new array escapes or that the type changes. Keeping the observation unknown is supported by the analyzer output.

The scout report gives target label `new:108922`; this replay gives `new:111634`. Both are internal synthetic labels: `src/ohscanner/detectors/ark_runtime/type_origin.py` constructs `new:<node.start_byte>`. The replay uses the same source commit/tree/blob/SHA and reproduces the same Map line, unknown kind, invalidation reason, creation/type-token lines, and `JSCallDispatch` effect site. I found no evidence that label generation is run-local or order-dependent; the differing byte-offset labels remain unexplained and are not evidence of a source mismatch.

## Conclusion

The independent controls reproduce the scout's raw-versus-expanded parser behavior and support the narrow explanation that these 13 issues arise from unexpanded macros and associated parse cascades. The array initializer alone parses completely. The Map 2747 observation remains an effect-related `unknown` tied to a possible `JSCallDispatch` side effect. These are source/parser and local-analysis observations only; they make no product-build, exploitability, vulnerability, or safety claim.
