# Independent U32 TypedArray length boundary baseline — 2026-10-20

## Worktree and exact source objects

The dedicated test worktree was clean at start, HEAD `24412cc6083b3b8cad9b611a2b0303fd71eeceeb`. No production code or dependencies were changed. Parent and fixed objects were read from local store `D:\openHarmonyScanner\tmp\c8-i9k03b-baseline-source-20261019`.

| Role | Commit | Tree | File blob | File SHA-256 |
|---|---|---|---|---|
| parent | `3c1a50cfb1206ce63afcd2d0ef2b1e81668f2e3c` | `f86de4aedd95c719b6215273cf10ab15e26d99e4` | `c5153346369f0182e73098b8d008eca6d750b36d` | `4be243a68180be845defbcc01b259070db68b18da8500d245eea4929e7b9eca5` |
| fixed | `82c21d656880923800c94b53b035c76d219313b5` | `cfad2654abd1554b35b0817f43ca8585dd937106` | `89ffed8b3ff112a271c8a074967b7b5e8ebe2f6f` | `373f5babdd5dd2f93d01512901d02e6b39d6b57c636e72b07b8d80d27eb509ab` |

Both refer to `ecmascript/base/typed_array_helper.cpp`. The review report identities match. I also checked downstream source identities: `js_tagged_value.cpp`, `js_tagged_value.h`, `js_typed_array.h`, and `builtins_arraybuffer.cpp` have identical blob IDs and SHA-256 across parent and fixed. The parent/fixed diff in `typed_array_helper.cpp/.h` is the signed-to-unsigned type change at constructor conversion and `AllocateTypedArray` parameter; the downstream files are unchanged.

## Source order and boundary matrix

Exact parent/fixed source shows this order:

1. `JSTaggedValue::ToIndex` handles conversion, truncates with `NumberHelper::TruncateDouble`, and rejects `len < 0.0 || len > SAFE_NUMBER` (`SAFE_NUMBER = 9007199254740991`).
2. After abrupt-completion handling, parent casts `index.GetNumber()` to `int32_t`; fixed casts to `uint32_t`; the same-width parameter is passed into `AllocateTypedArray`.
3. `AllocateTypedArrayBuffer` compares the received `uint64_t length` to `MAX_TYPED_ARRAY_INDEX`, which aliases `MAX_ELEMENT_INDEX == UINT32_MAX`.
4. It calculates `uint64_t byteLength = elementSize * length`. Values above `MAX_ONHEAP_LENGTH` (`512 * 8`) route through `BuiltinsArrayBuffer::AllocateArrayBuffer`; that routine rejects `byteLength > INT_MAX` before narrowing accepted byteLength to `uint32_t` and creating the backing data.

These are source-order checks only. They do not prove runtime reachability, successful allocation, or a product effect. Out-of-range floating-to-integer conversions are not modeled as modulo/wrap; their result remains unknown without a specified compiler/runtime execution.

| Input `n` | `ToIndex` result | Parent `int32_t` cast | Fixed `uint32_t` cast | Later source checks, if a defined representable value reaches them |
|---:|---|---|---|---|
| `-1` | Reject before cast | not reached | not reached | not reached |
| `0` | Accept | representable | representable | zero byte length; control path |
| `INT32_MAX` (`2147483647`) | Accept | representable | representable | index check passes; 1-byte type gives byteLength exactly `INT_MAX`; larger element sizes exceed `INT_MAX` |
| `INT32_MAX + 1` (`2147483648`) | Accept | out of `int32_t` range; result unknown | representable | fixed path passes `UINT32_MAX` index ceiling, then byteLength is greater than `INT_MAX` for every element size >= 1 |
| `UINT32_MAX - 1` (`4294967294`) | Accept | out of `int32_t` range; result unknown | representable | fixed path passes index ceiling, then byteLength exceeds `INT_MAX` |
| `UINT32_MAX` (`4294967295`) | Accept | out of `int32_t` range; result unknown | representable | fixed path passes index ceiling, then byteLength exceeds `INT_MAX` |
| `UINT32_MAX + 1` / `2^32` (`4294967296`) | Accept | out of `int32_t` range; result unknown | out of `uint32_t` range; result unknown | no downstream conclusion from the cast result |
| `2^32 + 1` (`4294967297`) | Accept | out of `int32_t` range; result unknown | out of `uint32_t` range; result unknown | no downstream conclusion from the cast result |
| `SAFE_NUMBER` (`9007199254740991`) | Accept | out of `int32_t` range; result unknown | out of `uint32_t` range; result unknown | no downstream conclusion from the cast result |
| `SAFE_NUMBER + 1` (`9007199254740992`) | Reject before cast | not reached | not reached | not reached |
| `1.75` | Truncate to `1`, then accept | representable | representable | small length control |
| `2^32 + 0.75` | Truncate to `2^32`, then accept | out of `int32_t` range; result unknown | out of `uint32_t` range; result unknown | no downstream conclusion from the cast result |

Source-level counterevidence: fixed conversion values strictly greater than `INT32_MAX` and no greater than `UINT32_MAX` are representable at the cast and satisfy the typed-array index ceiling, but their positive byteLength exceeds `INT_MAX` for any TypedArray element size and is rejected before backing allocation. For `INT32_MAX`, whether the later byteLength check rejects depends on element size; no allocation-success claim follows even when the check permits the request. Parent behavior for values outside `int32_t` range and either version above `UINT32_MAX` is deliberately unknown at the conversion boundary.

The repo's synthetic `length_safe.cpp` control is a different path (`MakeEmpty` rejects nonzero lengths before allocation), so it is not treated as a direct behavioral oracle for the constructor pair. The exact fixed commit above is the relevant source-level fixed control. No runtime tests were run.

## Developer replay status

Developer supplied the exact requested input values and source-order expectations; those are independently recorded above. The developer worktree was still clean at base `7dc34a6995763691143d4575c0dd81049794f18`, with no implementation/test commit yet when this baseline was prepared. Therefore this report makes no same-commit detector claim. I will replay the developer's exact case matrix after receiving its commit and compare every downstream check and safe/fixed control.

## Limits

This baseline is a manual source trace of two pinned revisions plus boundary arithmetic. It is not a runtime reproduction, compiler-semantics experiment, detector evaluation, product build, vulnerability validation, or accuracy measurement. In particular, no conversion outside the destination integer range is assigned a wrap result.
