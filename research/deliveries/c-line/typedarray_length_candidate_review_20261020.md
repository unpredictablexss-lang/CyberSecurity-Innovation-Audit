# TypedArray length candidate: second-layer source review

Date: 2026-10-20  
Candidate: `I7W51D` / `ark.runtime.typedarray-length-signed-to-unsigned-narrowing`  
Classification: source-level candidate; runtime behavior and product impact unknown.

## Exact source binding

| Role | Commit | Tree | Path | Blob | SHA-256 |
|---|---|---|---|---|---|
| Parent | `3c1a50cfb1206ce63afcd2d0ef2b1e81668f2e3c` | `f86de4aedd95c719b6215273cf10ab15e26d99e4` | `ecmascript/base/typed_array_helper.cpp` | `c5153346369f0182e73098b8d008eca6d750b36d` | `4be243a68180be845defbcc01b259070db68b18da8500d245eea4929e7b9eca5` |
| Fixed | `82c21d656880923800c94b53b035c76d219313b5` | `cfad2654abd1554b35b0817f43ca8585dd937106` | `ecmascript/base/typed_array_helper.cpp` | `89ffed8b3ff112a271c8a074967b7b5e8ebe2f6f` | `373f5babdd5dd2f93d01512901d02e6b39d6b57c636e72b07b8d80d27eb509ab` |

The identities were verified from the local Ark Runtime Git object store and match the source-bound replay artifact. Candidate role labels describe the replay pair and do not establish ground truth.

## Source review

In the parent, `TypedArrayConstructor` calls `JSTaggedValue::ToIndex`, checks abrupt completion, then narrows the resulting number to `int32_t` before passing it to `AllocateTypedArray`. The fixed revision narrows to `uint32_t`, and the allocator parameter changes to `uint32_t`. `ToIndex` rejects negative values and values above `SAFE_NUMBER`, but permits positive values above the signed 32-bit range. This supports a real source-level signed-narrowing difference.

The allocation path supplies important counterevidence to an impact claim. The reviewed downstream source checks the length against `MAX_TYPED_ARRAY_INDEX`, computes byte length in `uint64_t`, and routes large allocations through `AllocateArrayBuffer`, which rejects byte lengths above `INT_MAX`. Those checks mean the source change alone does not establish that the newly represented lengths can be successfully allocated or that they cause a security impact. The parent can reject some values earlier after signed conversion; the fixed path reaches later bounds checks.

Both revisions still narrow `ToIndex` to 32 bits. Values above `UINT32_MAX` may wrap in either version. This boundary is a separate source-analysis candidate; this review does not conclude whether downstream checks make it harmless or observable.

## Assessment and limits

- Keep the finding as a credible, narrowly described source-level narrowing candidate.
- Do not describe it as a demonstrated vulnerability, successful oversized allocation, or product impact. The parent/fixed `1 → 0` replay only shows that the local source pattern changed.
- Potential overbreadth: an alert interpreted as “the fix enables successful allocation of every length above `INT32_MAX`” is not supported by the downstream range checks.
- Trigger behavior in a running VM, exceptions and observable behavior at boundary values, and shipped-product/runtime impact remain unknown. No runtime reproduction or product validation was performed.
- The `uint32_t` truncation boundary above `UINT32_MAX` remains unreviewed and should be analyzed independently with exact source-bound positive and negative cases.

