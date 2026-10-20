# Float32Array negative-double constructor candidate: independent source review

Date: 2026-10-20. Scope is source semantics only. No detector code was edited, and no product/runtime test was run.

## Disposition

The `TDouble(-1.0)` source candidate survives review. The candidate path has an explicit lower-bound check for tagged integers but no corresponding lower-bound check for tagged doubles in both the CommonStub and TypedHCR lowering. An exact `-1.0` converts to `int32(-1)`, converts back to `-1.0`, satisfies `doubleLength <= JSObject::MAX_GAP`, and enters the allocation fast path. A public builtin can return an integer-valued number in TDouble representation: `Math.ceil(-1.1)` reaches `BuiltinsMath::Ceil`, whose `CeilInternal` returns `GetTaggedDouble(std::ceil(value))`; `GetTaggedDouble` constructs `JSTaggedValue(double)`, whose constructor stores the double encoding directly. Passing that result to `new Float32Array(...)` is therefore a plausible source-level trigger for the fast path.

The downstream allocator behavior differs materially by pointer width. `NewByteArray` zero-extends the signed `int32` length before size calculation. For `-1`, this is `0xffffffff` on the target pointer width, not sign extension to a negative pointer value. On a 64-bit target, multiplying by element size 4 yields `0x3fffffffc`; adding the 16-byte ByteArray data offset and aligning to 8 gives `0x400000010` bytes (16 GiB + 16). The initialization end offset is then truncated back to `int32`, yielding `16`; because `InitializeWithSpeicalValue` takes absolute start/end offsets, this means an empty range `[16,16)`, not a 16-byte write. The typed-array metadata still stores length `-1` (as uint32 bits `0xffffffff`) and byte length `-4` (bits `0xfffffffc`). Allocation may fail, trigger huge-object/OOM behavior, or succeed depending on runtime configuration and available memory; I cannot infer the observable result from source alone.

On a 32-bit target, pointer-sized multiplication/addition wrap modulo 2^32: `4 * 0xffffffff + 16` becomes `12`, and 8-byte alignment yields `16`. The initializer again receives `[16,16)`, so the earlier concern that initialization itself writes beyond this allocation is refuted. However, the constructed TypedArray records uint32 length `0xffffffff` and byteLength `0xfffffffc` while its ByteArray backing allocation is only 16 bytes. The C++ runtime getter `JSTypedArray::FastGetPropertyByIndex` compares its uint32 index against the uint32 length, then computes the byte offset from the supplied JSType and calls the raw buffer reader; index 0 is in range by that metadata but has no backing data bytes. This supports a conditional follow-on OOB-read hypothesis if a user-reachable runtime path invokes this helper on the malformed object. Counterevidence: the inline CommonStub `FastGetPropertyByIndex` uses signed `Int32GreaterThanOrEqual(index, arrLen)` and would reject ordinary nonnegative indices when `arrLen` contains `0xffffffff`; it may return `undefined` before the raw read. Whether runtime fallback/deoptimization or another path reaches the uint32 C++ helper for this case is unknown. Product 32-bit build availability, stub execution, and heap behavior are also unverified. This is not a confirmed memory-corruption result.

## Source pins

All files below are from `openharmony/arkcompiler_ets_runtime`, commit `a65a2853ccae13da167d9aa4720ab8b11ec16656`, tree `8781f036a3e7e04d8e0b34970d5f623b42875016`, in `D:\openHarmonyScanner\tmp\c-line-ark-history-full-snapshots-20261018.git`.

| Path | Git blob | Source role |
|---|---|---|
| `ecmascript/compiler/common_stubs.cpp` | `6267f2f27a98a298b1190e327abbfa2bd58203f8` | Fast constructor stub; tagged-int nonnegative guard; double conversion/equality/upper-bound branch |
| `ecmascript/compiler/typed_hcr_lowering.cpp` | `1ad4e329a226fc9941db30fa7a10a6562f58f68d` | `ConvertFloat32ArrayConstructorLength` and matching optimized constructor lowering |
| `ecmascript/compiler/new_object_stub_builder.cpp` | `991ac5ac034a1a027e3200787ec25c55b3f15b69` | `NewFloat32ArrayWithSize`, `NewByteArray`, allocation failure edges |
| `ecmascript/compiler/stub_builder-inl.h` | `c0521ab7a55cd63850736c2db8a290115965373c` | `ComputeTaggedTypedArraySize` pointer-width arithmetic |
| `ecmascript/byte_array.h` | `82780d249f5170b4ec5bf0474e71fd1cb110b67a` | ByteArray offsets and data layout; `DATA_OFFSET` is aligned and equals `SIZE` |
| `ecmascript/mem/heap-inl.h` | `b6f3d17e770cdaa2252bc3c571675d72dff0a9c7` | Young/huge-object allocation and OOM behavior |
| `ecmascript/stubs/runtime_stubs.cpp` | `14dc06350881b1fa0fdabeeb8465ae9063224d6c` | `AllocateInYoung` runtime helper |
| `ecmascript/builtins/builtins_math.cpp` | `874f47589056ac791b599089bdfa6083083a83d3` | `CeilInternal` returns `GetTaggedDouble(ceil(value))` |
| `ecmascript/base/builtins_base.h` | `6ecbcb646749bb8815961f4ac6e6212e9b555e16` | `GetTaggedDouble(double)` wraps a `JSTaggedValue(double)` |
| `ecmascript/js_tagged_value.h` | `c99f554ffb146b57ad2dca7d51771a2b3662e801` | `JSTaggedValue(double)` stores a TDouble encoding directly |
| `ecmascript/compiler/builtins/builtins_call_signature.cpp` | `94861dd0e64d794db0476e4f1adc1e41b1f7ae8c` | Float32Array constructor builtin identity mapping |
| `ecmascript/compiler/lcr_circuit_builder.cpp` | `a6df4cba87c9a49f09a292648e7ea7d7cad1b24c` | `TruncDoubleToInt` lowering in TypedHCR path |
| `ecmascript/compiler/stub_builder.cpp` | `c630a6200215705843d11c0dd86c565709e8c6c4` | `DoubleToInt` lowering in CommonStub path |
| `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp` | `68fb3b0adc4f9062889a861be51b7be90362e37a` | Fast getter uses signed int32 logical-length guard before raw load |
| `ecmascript/js_typed_array.cpp` | `098c2a22cae3152af3a59063dda25e145f03bbd7` | Runtime getter uses uint32 logical-length guard and supplied-type byte width |

The first three paths and their SHA-256/parse statuses are also pinned in `c_exact_bound_scout_20261020.md`. This review does not upgrade any parser status or claim a complete detector trace.

## Trigger, argument conversion, and controls

In `NewFloat32ArrayStubBuilder::GenerateCircuit`, `TaggedIsNumber(arg0)` is followed by `TaggedIsInt(arg0)`. The tagged-int branch requires `intLen >= 0` and `intLen <= JSObject::MAX_GAP`. The TDouble branch computes `doubleToInt = DoubleToInt(..., INT32_BITS)`, widens that int back to double, and branches on `DoubleEqual(doubleLength, intToDouble)` and `doubleLength <= MAX_GAP`. For finite `-1.0`, `ChangeFloat64ToInt32` yields `-1`; CommonStub's overflow branch is not taken for this representable value. The round-trip is exactly `-1.0`, and the upper bound passes. The lower-bound predicate is absent. The branch sign-extends `-1` into `arrayLength` and truncates it back to `int32(-1)` before calling `NewFloat32ArrayWithSize`.

`TypedHCRLowering::ConvertFloat32ArrayConstructorLength` has the same split and the same missing negative check. Its `TruncDoubleToInt` implementation begins with `ChangeFloat64ToInt32` and uses a runtime conversion only on overflow, so the exact `-1.0` case has the same source result. The typed HCR fast call then truncates the accepted `arrayLength` to `int32` and calls the same object builder.

The public-value representation path is supported at source level: `BuiltinsMath::Ceil` invokes `CeilInternal`; for finite input, `CeilInternal` returns `GetTaggedDouble(std::ceil(value))`; `GetTaggedDouble` constructs `JSTaggedValue(double)`, whose constructor writes the encoded double without converting integral values to tagged integers. Thus `Math.ceil(-1.1)` can produce a double-tagged `-1.0` for the constructor argument. `builtins_call_signature.cpp` includes the `Float32ArrayConstructor` mapping, while the HCR lowering explicitly handles `FLOAT32_ARRAY_CONSTRUCTOR`. Exact selection/execution of either fast path in a product runtime remains build- and execution-dependent.

Useful source controls: tagged-int `-1` fails its lower-bound check and takes runtime construction; TDouble `-0.5` fails exact round trip; TDouble `1025.0` fails the upper bound; positive integral TDouble passes both checks and allocates its positive requested length. NaN/infinities are intentionally not used as evidence because conversion overflow behavior is a separate path.

## Allocation arithmetic and counterevidence

`NewFloat32ArrayWithSize` computes `newByteLength` with `Int32Mul(size, 4)`, then unconditionally requests a ByteArray. In `NewByteArray`, `ComputeTaggedTypedArraySize` is `DATA_OFFSET + elementSize * length`; both `elementSize` and `length` are converted with `ZExtInt32ToPtr` before pointer-width multiplication. It aligns the result to object alignment and stores that pointer-sized value in `size_`. The allocator's fast path uses `top + size_`; if the object does not fit it calls the `AllocateInYoung` runtime stub with the tagged size. After allocation, `InitializeWithSpecialValue` receives `start=ByteArray::DATA_OFFSET` and `end=TruncPtrToInt32(size)`, so a truncated end equal to 16 yields an empty initialization range rather than an overflow write. The ByteArray then stores its original `length` and element size as uint32 metadata.

This arithmetic is enough to show an invalid negative length bypasses the constructor fast-path guard and reaches allocation, but not enough to claim reliable allocation or overwrite: pointer width, heap configuration, large-object threshold, OOM handling, GC mode, generated lowering, and platform selection control the outcome. On 64-bit, the size is very large and may fail or cause memory pressure; it may only be a denial-of-service path if no allocation succeeds. On 32-bit, pointer arithmetic wraps to a 16-byte allocation; the empty initialization interval refutes an immediate overwrite, while mismatched large metadata and empty backing payload create a conditional later-access concern. The signed inline getter guard is explicit counterevidence against a simple fast indexed access; the runtime C++ helper has unsigned behavior, but source-only review cannot prove JS can route to it for this malformed instance. The current source checkout provides no project build profile or executed product build to establish either case. The `length=0xffffffff` metadata is contrary to constructor length semantics, even if allocation failure prevents a usable object.

There is no source-level countercheck for negative TDouble in the fast-path predicates, and the exact public Math.ceil route undermines the concern that source JavaScript can only supply integer-tagged `-1`. The principal counterevidence/unknown is operational: optimized/common constructor stub selection may be configuration-dependent, and allocator/OOM behavior may prevent the object from becoming observable. That limits the conclusion to a source candidate.

## Smallest isolated runtime experiment

In an isolated Ark Runtime build, run these cases in a fresh process with heap/ASan logs retained:

```javascript
const fromDouble = Math.ceil(-1.1); // Math.ceil source path returns TDouble(-1.0)
new Float32Array(fromDouble);
new Float32Array(-1);               // tagged-int negative control; should take runtime slow path/throw
new Float32Array(Math.ceil(1.1));   // positive integral TDouble control
new Float32Array(Math.ceil(-0.1));  // negative-zero normalization control
```

Instrument immediately before `NewFloat32ArrayWithSize` to record whether the argument is tagged int or tagged double, the selected CommonStub/TypedHCR path, and the signed `size`. Instrument `NewByteArray` to record pointer width, `size_`, `[start,end)` initialization interval, and allocation result. Run each supported 32-bit and 64-bit build separately. On 32-bit, use ASan to inspect indexed reads/writes on the returned object, while separately tracing whether JS access uses the signed inline helper or uint32 runtime helper; do not treat the empty initializer range as an overflow. Assert language-level result/exception and inspect stored TypedArray and ByteArray metadata/backing extent. Include positive integral-TDouble and tagged-int `-1` controls to prove the behavior depends on representation. A local debug build/run is the smallest useful discriminator; no shared or production service is involved.

No runtime/build/ASan result is asserted here. The detector has no registered source binding/rule for this path in the reviewed branch, and this report does not propose or implement one.

