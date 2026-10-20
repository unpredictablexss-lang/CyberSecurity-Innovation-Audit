# Float32Array negative-TDouble candidate: independent runtime test audit

Date: 2026-10-20. Independent adversarial follow-up to the exact-bound scout and second-layer review. No production source or task tree was changed.

## Result

No compatible built Ark Runtime executable or build tree was present in the inspected local source/build locations, so runtime behavior was **not run**. There is no 32-bit or 64-bit execution result, allocation result, sanitizer result, or product confirmation in this report.

Independent arithmetic review confirms the second-layer report's main allocation calculations for `TDouble(-1.0)`:

- `NewFloat32ArrayWithSize` receives signed int32 `-1`; its `Int32Mul(-1, 4)` produces bit pattern `0xfffffffc` (-4).
- `NewByteArray` passes `ZExtInt32ToPtr(elementSize)` and `ZExtInt32ToPtr(length)` into `DATA_OFFSET + elementSize * length`, then aligns to 8 bytes. For `DATA_OFFSET=16` and element size 4, the 64-bit result is `AlignUp(0x40000000c, 8) = 0x400000010` (16 GiB + 16). On 32-bit arithmetic it wraps to 12 before alignment, yielding allocation size 16.
- The initializer uses `start=16`, `end=TruncPtrToInt32(size)`. Both pointer-width cases produce `end=16`, hence an empty `[16,16)` range. The earlier immediate-initializer-overwrite concern is refuted.
- The 32-bit object would still contain mismatched metadata: TypedArray `ARRAY_LENGTH=-1` / bits `0xffffffff`, TypedArray `BYTE_LENGTH=-4` / bits `0xfffffffc`; backing ByteArray `ARRAY_LENGTH=-1` / bits `0xffffffff` and `BYTE_LENGTH=4`; backing allocation size 16 with data offset 16 and no data payload. These are raw `uint32`/`int32` bit patterns, not proof that construction or later access succeeds.

I found an important qualification to the second-layer getter counterevidence. The inline TypedArray builtin stub's `Int32GreaterThanOrEqual(index, arrLen)` is a signed int32 comparison and would reject index 0 when `arrLen` has bits `0xffffffff`; that specific builtin-stub path exits with `undefined`. However, ordinary indexed-property IC miss has a distinct C++ path: `LoadTypedArrayValueMiss` first checks `IsValidIntegerIndex`, converts the nonnegative numeric index to `uint32_t`, and directly calls `JSTypedArray::FastGetPropertyByIndex`. That C++ helper also takes `uint32_t index`, reads `uint32_t arrLen`, and checks `index >= arrLen`. For index 0 and `arrLen=0xffffffff`, the check passes. It then calls `GetValueFromBuffer` using the ByteArray-backed buffer. Thus the signed inline-stub check does not by itself rule out a 32-bit ordinary indexed-read path; source supports a conditional out-of-bounds-read hypothesis if the malformed object is created and the C++ path reads past the empty backing data. The exact IC entry, backing pointer access, heap layout, and observable result remain unexecuted, so this is not a demonstrated OOB read.

Fast-getter signatures reviewed:

- Compiler builtin stub: `GateRef ...FastGetPropertyByIndex(... GateRef index, ...)`, guarded with `Int32GreaterThanOrEqual` before loading.
- Runtime C++ helper: `JSTypedArray::FastGetPropertyByIndex(..., uint32_t index, JSType jsType)`, using unsigned `uint32_t arrLen` comparison.
- Ordinary IC miss: `LoadICRuntime::LoadTypedArrayValueMiss` (`ecmascript/ic/ic_runtime.cpp`) calls the C++ helper after `IsValidIntegerIndex`; `ICRuntimeStub::LoadTypedArrayElement` (`ecmascript/ic/ic_runtime_stub-inl.h`) also compares unsigned values. These routes are not signature-equivalent to the builtin stub and are not proven to share its signed guard.

## Exact source and commands

Source repository: local Ark Runtime object store `D:\openHarmonyScanner\tmp\c-line-ark-history-full-snapshots-20261018.git`; commit `a65a2853ccae13da167d9aa4720ab8b11ec16656`; tree `8781f036a3e7e04d8e0b34970d5f623b42875016`.

Read-only source commands used (PowerShell):

```powershell
git --git-dir=D:\openHarmonyScanner\tmp\c-line-ark-history-full-snapshots-20261018.git show a65a2853ccae13da167d9aa4720ab8b11ec16656:ecmascript/compiler/common_stubs.cpp
git --git-dir=D:\openHarmonyScanner\tmp\c-line-ark-history-full-snapshots-20261018.git show a65a2853ccae13da167d9aa4720ab8b11ec16656:ecmascript/compiler/new_object_stub_builder.cpp
git --git-dir=D:\openHarmonyScanner\tmp\c-line-ark-history-full-snapshots-20261018.git show a65a2853ccae13da167d9aa4720ab8b11ec16656:ecmascript/js_typed_array.cpp
git --git-dir=D:\openHarmonyScanner\tmp\c-line-ark-history-full-snapshots-20261018.git show a65a2853ccae13da167d9aa4720ab8b11ec16656:ecmascript/ic/ic_runtime.cpp
git --git-dir=D:\openHarmonyScanner\tmp\c-line-ark-history-full-snapshots-20261018.git show a65a2853ccae13da167d9aa4720ab8b11ec16656:ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp
git --git-dir=D:\openHarmonyScanner\tmp\c-line-ark-history-full-snapshots-20261018.git grep -n FastGetPropertyByIndex a65a2853ccae13da167d9aa4720ab8b11ec16656 -- ecmascript
```

Runtime/build discovery checked `D:\openHarmonyScanner\tmp\c-line-test-checkout-a65-linked-20261018`, `D:\openHarmonyScanner\openharmony\out`, and `D:\openHarmonyScanner\artifact_build` for `ark_js_vm`, `ark_aot_compiler`, and `libark_jsruntime` artifacts; none were found. The local `openharmony\out` contained only `dfx`, `hb_args`, `preloader`, and `rk3568` directories, with no matching runtime executable/library. No build or runtime command was launched.

## Unexecuted items and controls

Not run: 32-bit runtime, 64-bit runtime, `Math.ceil(-1.1)` representation confirmation, tagged-int negative control, positive TDouble control, `-0` normalization control, allocation/exception outcome, ordinary direct index read, builtin indexed read, ASan, heap/metadata inspection, or product build/profile. Existing source-derived controls remain predictions only. A usable 32-bit Ark build is the decisive next discriminator for the possible malformed-object read; a 64-bit build would clarify only huge-allocation failure/behavior.

Disposition: constructor predicate gap remains a source-level candidate. The 32-bit follow-on is more plausible than the second-layer report's inline-stub-only counterevidence suggests, because a separate unsigned C++ IC-miss route exists. Neither runtime path nor security impact has been established by execution.
