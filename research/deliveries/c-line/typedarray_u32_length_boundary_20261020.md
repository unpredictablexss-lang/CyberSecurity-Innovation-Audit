# TypedArray `uint32_t` length boundary review — 2026-10-20

## Result

No production or test patch is justified for the adjacent `> UINT32_MAX` slice. The exact fixed source accepts `ToIndex` values through `SAFE_NUMBER` before converting the resulting `double` to `uint32_t`, but the C++ floating-to-integer conversion is out of range above `UINT32_MAX`; this review does not assume modulo, wrapping, or any concrete runtime result. That uncertainty cannot support an additional detector finding. The earlier `I7W51D` signed-narrowing source candidate remains a separate, previously reviewed observation; this report does not downgrade or reclassify it.

## Exact source identity

Source objects came from the local Git object store `D:\openHarmonyScanner\tmp\c-line-ark-near-parent-20261020.git`.

| Revision | Commit | Tree | `typed_array_helper.cpp` blob | SHA-256 |
|---|---|---|---|---|
| Parent | `3c1a50cfb1206ce63afcd2d0ef2b1e81668f2e3c` | `f86de4aedd95c719b6215273cf10ab15e26d99e4` | `c5153346369f0182e73098b8d008eca6d750b36d` | `4be243a68180be845defbcc01b259070db68b18da8500d245eea4929e7b9eca5` |
| Fixed | `82c21d656880923800c94b53b035c76d219313b5` | `cfad2654abd1554b35b0817f43ca8585dd937106` | `89ffed8b3ff112a271c8a074967b7b5e8ebe2f6f` | `373f5babdd5dd2f93d01512901d02e6b39d6b57c636e72b07b8d80d27eb509ab` |

The source difference at `TypedArrayConstructor` is `static_cast<int32_t>(index.GetNumber())` in parent versus `static_cast<uint32_t>(index.GetNumber())` in fixed. `ToIndex` is identical across the pair, as are `js_typed_array.h` and `builtins_arraybuffer.cpp`. The fixed revision has `MAX_TYPED_ARRAY_INDEX == UINT32_MAX`.

## Boundary trace

`JSTaggedValue::ToIndex` first converts to number, truncates with `TruncateDouble`, and throws for values below zero or above `SAFE_NUMBER`. Thus `-1` and `SAFE_NUMBER+1` are rejected before the cast; fractional inputs such as `1.75` are truncated to `1`. Nonnegative values up to `SAFE_NUMBER` can reach the constructor cast.

The parent/fixed cast and subsequent source checks give these limited conclusions:

| Input length | Parent `int32_t` cast | Fixed `uint32_t` cast | Later source behavior |
|---|---|---|---|
| `0` through `INT32_MAX` | representable | representable | Enters the typed-array allocator; successful allocation is not asserted here. |
| `INT32_MAX+1` through `UINT32_MAX` | out of signed range; result not inferred | representable | Index ceiling permits the value. `byteLength` is computed as `uint64_t(elementSize) * length`; `AllocateArrayBuffer` rejects `byteLength > INT_MAX` for every element size at least one, before backing allocation. No allocation success or bypass is claimed. |
| `UINT32_MAX+1` through `SAFE_NUMBER` | out of signed range | out of destination range for floating-to-integer conversion | `ToIndex` permits the source value, but the cast's result/runtime behavior is unknown here. The subsequent check cannot establish defined conversion semantics. |
| `< 0` or `> SAFE_NUMBER` | cast not reached | cast not reached | `ToIndex` throws first. |

The downstream order is cast, `AllocateTypedArrayBuffer` max-index check, `uint64_t` byte-length multiplication, then `AllocateArrayBuffer`'s `byteLength > INT_MAX` rejection. These checks explain why the fixed representable interval above `INT32_MAX` does not demonstrate successful backing allocation. They do not resolve behavior for a conversion outside `uint32_t` range.

## Detector coverage and replay status

I directly invoked the repository's generic `CppIntegerBoundsDetector.detect` on `SourceUnit`s extracted from the exact parent and fixed target blobs. It returned 0 findings for parent and 0 for fixed. This is a detector-specific not-match, not a registered Ark Runtime replay.

The current Ark Runtime detector model has no typed-array length-narrowing rule or exact bindings for these two commits/path. Therefore the requested registered Ark Runtime CLI replay is **not_run** on this base; no CLI candidate/suppression claim is made. Existing Ark Runtime size-overflow analysis covers a different multiplication-flow pattern and is not treated as a length-conversion rule.

## Validation and limitations

Command: `python -m pytest tests/detectors/ark_runtime tests/detectors/test_cpp_memory_safety_detectors.py -q`

Result: **179 passed, 3 skipped**. An earlier attempted test path `tests/detectors/test_cpp_integer_bounds_detector.py` does not exist; that command collected no tests and was replaced by the actual memory-safety detector suite above.

The independent tester's source-baseline report is commit `58792ad3f266a8e25e66a24469f81548d138bafd`, file `research/deliveries/c-line/u32_length_independent_baseline_20261020.md` in its test worktree. Its findings agree with the source trace above. No compiler/runtime execution, product build context, allocation-success evidence, or exploitability assessment was performed. Parser/build-profile and product impact remain unknown.
