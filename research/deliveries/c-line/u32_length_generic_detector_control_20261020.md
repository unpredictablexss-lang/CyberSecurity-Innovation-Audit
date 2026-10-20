# U32 TypedArray length: generic detector direct control

This is an independent follow-up to `u32_length_independent_baseline_20261020.md`. It checks only the generic `CppIntegerBoundsDetector` direct API on the pinned parent and fixed source units. It is not a registered Ark Runtime replay, runtime execution, or product result.

## Reproduction

In the test worktree, I read `ecmascript/base/typed_array_helper.cpp` directly from local Git source repository `D:\openHarmonyScanner\tmp\c8-i9k03b-baseline-source-20261019`, computed SHA-256 over the exact bytes, parsed those bytes with the installed `tree_sitter_cpp` grammar, and passed a `SourceUnit` to `CppIntegerBoundsDetector.detect`. The context used a fixture request because this direct detector invocation does not establish Ark Runtime model/source binding. Exact invocation shape:

```python
raw = subprocess.check_output(["git", "-C", source_repo, "show", f"{commit}:{path}"])
tree = Parser(Language(tree_sitter_cpp.language())).parse(raw)
parse_status = "partial" if tree.root_node.has_error else "complete"
unit = SourceUnit(path, "cpp", raw.decode("utf-8"), sha256(raw).hexdigest(), parse_status)
run = CppIntegerBoundsDetector().detect(context_for(unit), (unit,))
```

The repository helper constructs a fixture `ScanContext`; `context_for` is not a source-binding or Ark Runtime replay mechanism.

## Results

| Revision | Commit | Blob | SHA-256 | tree-sitter parse | Direct generic detector |
|---|---|---|---|---|---|
| Parent | `3c1a50cfb1206ce63afcd2d0ef2b1e81668f2e3c` | `c5153346369f0182e73098b8d008eca6d750b36d` | `4be243a68180be845defbcc01b259070db68b18da8500d245eea4929e7b9eca5` | no error, `translation_unit` | `completed`, target in analyzed files, 0 findings |
| Fixed | `82c21d656880923800c94b53b035c76d219313b5` | `89ffed8b3ff112a271c8a074967b7b5e8ebe2f6f` | `373f5babdd5dd2f93d01512901d02e6b39d6b57c636e72b07b8d80d27eb509ab` | no error, `translation_unit` | `completed`, target in analyzed files, 0 findings |

The exact runtime output for both rows was `tree_has_error False`, `parse_status complete`, `status completed`, `analyzed ('ecmascript/base/typed_array_helper.cpp',)`, and `findings 0`. The detector also reports its standing limitations: lexical integer arithmetic does not prove allocation undersizing or impact, and signedness, promotions, macros, templates, and interprocedural ranges remain unknown unless explicitly modeled.

As a fail-closed control, I reran each exact source unit with `parse_status='not_run'`. Both runs returned `status blocked`, no analyzed files, zero findings, and the explicit limitation `parse_status=not_run; integer coverage remains unknown.` Thus an unparsed zero-finding result must not be described as detector coverage.

## Interpretation and limits

The completed direct calls reproduce the generic detector's zero-finding output on both exact blobs. They do not demonstrate a length-specific rule, Ark Runtime model binding, rule applicability, or safety. This generic detector has lexical integer-boundary coverage with explicit limitations; a zero result here is not evidence that it models the `ToIndex` → narrowing conversion → typed-array allocation chain. The separately recorded source trace remains the basis for the source-order conclusions and unknown conversion semantics. No code or dependency was changed, and no runtime test was run.
