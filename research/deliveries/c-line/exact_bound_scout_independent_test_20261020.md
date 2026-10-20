# Exact-bound scout: independent tester result (2026-10-20)

## Result

Independent source review confirms one **conditional source-level candidate** in the Float32Array length fast path: both CommonStub and TypedHCR accept an exactly integral negative value when it is in the `TDouble` representation, because that branch checks integer round-trip equality and only the upper `MAX_GAP` bound. The tagged-integer branch does check nonnegativity. This merits a narrowly scoped source follow-up, but is not a runtime, vulnerability, or product-impact finding. TDouble reachability, allocator behavior, and product configuration were not executed.

I found no counterexample to the developer's closure of the adjacent `NewTypedArray` caller-bound, ByteArray and ArrayBuffer slice/clone hypotheses. The available static detector/model has no exact binding/rule for this constructor flow; its result must not be described as detector confirmation or rejection. No production changes were made.

## Pinned source and independent checks

All identities below are from Ark Runtime commit `a65a2853ccae13da167d9aa4720ab8b11ec16656` (tree `8781f036a3e7e04d8e0b34970d5f623b42875016`) in the local source object store.

| Source | Blob | SHA-256 | Independent finding |
|---|---|---|---|
| `ecmascript/compiler/common_stubs.cpp` | `6267f2f27a98a298b1190e327abbfa2bd58203f8` | `5a401580e666596fcf2ea89a8dc0321009b53ef5320b20edc59d37781d852212` | Double branch at lines 222–241 lacks lower bound; tagged-int branch checks `>= 0`. Earlier recorded Tree-sitter status: partial. |
| `ecmascript/compiler/typed_hcr_lowering.cpp` | `1ad4e329a226fc9941db30fa7a10a6562f58f68d` | `acd4ed88bb4ba5d327d5628dc45b7b89685a9c425c5849891cbf2544e8534a0c` | `ConvertFloat32ArrayConstructorLength` lines 2333–2412 repeats the missing lower bound, using `TruncDoubleToInt`. Earlier status: complete. |
| `ecmascript/compiler/stub_builder.cpp` | `c630a6200215705843d11c0dd86c565709e8c6c4` | `978f507daa99982b115f2db4e63ce629c653f011b4b998ac9e20255ab786b25a` | `DoubleToInt` uses `ChangeFloat64ToInt32`; overflow routes to `RTSTUB_ID(DoubleToInt)`. This runtime stub is not pinned here, so out-of-range/NaN/infinity behavior is left unknown. |
| `ecmascript/compiler/typed_hcr_lowering.cpp` | as above | as above | TypedHCR truncation implementation is `TruncInt64ToInt32(TruncFloatToInt64(x))`; exact small negative integers convert to their negative int32 value. |
| `ecmascript/compiler/new_object_stub_builder.cpp` | `991ac5ac034a1a027e3200787ec25c55b3f15b69` | `3159eee6989838659438af89353dfd37a890c259f60c3af0195110e016a411e0` | `NewFloat32ArrayWithSize` multiplies length by four and calls `NewByteArray`; the latter zero-extends length for allocation-size computation and stores original length as int32 metadata. Earlier status: complete. |
| `ecmascript/js_object.h` | `51ab43601b86cf75486888dbd5b4337340757b9a` | `ed1e88c4aad0c0dd69fb778e61ea6e3d78c90f05df13802a95622c6a69f1cd38` | `MAX_GAP = 1_KB` at line 418. Earlier status: partial. |

The trace is: for `-1.0`, int32 conversion yields `-1`; converting that int32 back to double equals the input, and `-1 <= 1024` is true. The accepted value is sign-extended then truncated to int32 and passed to `NewFloat32ArrayWithSize`. The same applies to `-1024.0`; indeed any exactly represented integral negative within the conversion's supported int32 range meets the shown double predicate. This proves a source predicate gap, not that the runtime supplies that representation or that allocation succeeds. No downstream nonnegative validation was found between either fast path and the helper call in the inspected source.

## Source-predicted controls (not executed)

| Input | Prediction from pinned branch conditions | Status |
|---|---|---|
| TDouble `-1`, `-1024` | round-trip equal and upper bound passes; fast path | Source-derived candidate control; compiler/runtime not run |
| TaggedInt `-1` | explicit `intLen >= 0` fails; slow path | Source-derived safe control |
| TDouble `-0.5` | truncation round-trip differs; slow path | Source-derived control |
| TDouble `-0`, `0`, `1`, `1024` | equality and upper bound pass | Source-derived ordinary-bound controls; signed-zero normalization not tested |
| TDouble `1025` | upper bound fails; slow path | Source-derived safe control |
| TDouble NaN / ±infinity / values outside int32 | runtime conversion-stub behavior is not pinned/executed | Unknown; excluded from evidence |

These are symbolic evaluations of source predicates, not executable compiler branch tests. No mutation/fixed-code, unrelated-function, or missing-evidence replay was run. Exact candidate files are not registered/bound to the current detector model, so there is no adapter/model positive or negative result for this flow.

## Adjacent hypotheses checked

- `NewTypedArray` callers for Map/Slice/ToReversed/ToSorted derive lengths from the source TypedArray; Filter's result count is bounded by source length. For matching source/result element type, byte size is bounded by backing `ByteLength`. The reviewed allocators cap ordinary ArrayBuffer lengths at `INT_MAX` and on-heap ByteArray at 4096 bytes. `NewTypedArrayFromCtor` is reached from `Of` with argument count capped at three. No reachable size-overflow route was found in this scoped caller review.
- ByteArray `GetOffHeapBuffer` cast is bounded by the same on-heap 4096-byte gate in the reviewed path. ArrayBuffer Slice/Clone offsets/spans are clamped or rely on checked caller invariants, and backing allocation is capped. No concrete counterexample was found.
- DataView `GetTypedValue` uses a 64-bit unsigned `index + elementSize` comparison before adding byte offset. No additional candidate found.

## Limits and disposition

Not run: C++ build, compiler graph execution, runtime tests, sanitizers, product build/profile, or end-to-end representation-reachability test. Allocator failure/exception propagation and later use of a negative-length object remain unknown. Thus the independent result is **one source-level candidate, follow-up warranted; no confirmed runtime issue**. The unexecuted control matrix above must not be reported as tests passed.
