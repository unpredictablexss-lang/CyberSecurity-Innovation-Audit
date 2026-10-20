# Exact-bound C-line scout: one Float32Array constructor candidate (2026-10-20)

## Disposition

One conditional source-level candidate merits independent follow-up: the Float32Array constructor fast path appears to accept a negative integer when the numeric argument is represented as a `TDouble`. The int-tagged branch rejects negative values, but the double branch checks round-trip equality and only an upper length bound. This is not a runtime/product vulnerability conclusion; representation reachability and allocator consequences have not been executed. No production code was changed in this scout.

The remaining inspected ArrayBuffer copy/slice/clone and TypedArray storage-size paths did not yield another candidate. Previously completed Map, TypedArray length, IB8BCA `SetTypedValue`, DataView API-width, receiver-guard, and C1 adapter slices were excluded from re-analysis.

## Exact source and baseline

Upstream source: Ark Runtime commit `a65a2853ccae13da167d9aa4720ab8b11ec16656`, tree `8781f036a3e7e04d8e0b34970d5f623b42875016`, read from local object store `D:\openHarmonyScanner\tmp\c-line-ark-history-full-snapshots-20261018.git`.

The candidate path is pinned to:

- `ecmascript/compiler/common_stubs.cpp`, blob `6267f2f27a98a298b1190e327abbfa2bd58203f8`, SHA-256 `5a401580e666596fcf2ea89a8dc0321009b53ef5320b20edc59d37781d852212`, Tree-sitter partial. `NewFloat32ArrayStubBuilder::GenerateCircuit` begins at line 186; double conversion and upper-bound-only fast-path checks are at lines 222–241.
- `ecmascript/compiler/typed_hcr_lowering.cpp`, blob `1ad4e329a226fc9941db30fa7a10a6562f58f68d`, SHA-256 `acd4ed88bb4ba5d327d5628dc45b7b89685a9c425c5849891cbf2544e8534a0c`, Tree-sitter complete. `ConvertFloat32ArrayConstructorLength` begins at line 2333; corresponding double checks and fast-path call are at lines 2350–2412.
- `ecmascript/compiler/new_object_stub_builder.cpp`, blob `991ac5ac034a1a027e3200787ec25c55b3f15b69`, SHA-256 `3159eee6989838659438af89353dfd37a890c259f60c3af0195110e016a411e0`, Tree-sitter complete. `NewFloat32ArrayWithSize` is at lines 3042–3074; `NewByteArray` at lines 3119 onward.
- `ecmascript/js_object.h`, blob `51ab43601b86cf75486888dbd5b4337340757b9a`, SHA-256 `ed1e88c4aad0c0dd69fb778e61ea6e3d78c90f05df13802a95622c6a69f1cd38`, Tree-sitter partial; `JSObject::MAX_GAP = 1_KB` at line 418.

The currently bound C-line Ark model has no target binding or registered rule for these constructor-source files. Direct `analyze_unit` on exact `builtins_arraybuffer.cpp` returns `completed/complete`, zero observations, and `not_applicable_to_rule`; this does not cover the constructor flow. Direct C1 TypedArray stub analysis remains `limited/partial` with helper-effect unknowns. No existing detector finding for this hypothesis is claimed.

## Candidate trace

In `common_stubs.cpp`, the tagged-int branch requires `intLen >= 0` and `intLen <= JSObject::MAX_GAP`. In the double branch, the source computes `doubleToInt = DoubleToInt(glue, doubleLength, INT32_BITS)`, converts that result back to double, and checks `DoubleEqual(doubleLength, intToDouble)` plus `doubleLength <= MAX_GAP`; there is no corresponding `doubleLength >= 0` check. The accepted value is sign-extended into `arrayLength`, then truncated to `int32` and sent to `NewFloat32ArrayWithSize`. The `TypedHCRLowering` implementation has the same missing lower-bound check, using `TruncDoubleToInt`.

For an exact integral negative `TDouble`, such as `-1.0`, the narrow source operations plausibly yield `doubleToInt == -1`, the round-trip equality is true, and the upper-bound comparison is true. The fast path therefore passes `-1` to `NewFloat32ArrayWithSize`. That helper multiplies size by four in `Int32`, then unconditionally calls `NewByteArray`. `NewByteArray` zero-extends the `int32` length to pointer width for `ComputeTaggedTypedArraySize`/allocation, then truncates the computed pointer-sized allocation size back to `int32` for initialization and stores the original length as `int32` metadata. This is a plausible negative-length-to-large-allocation/invalid-metadata path; exact allocator failure behavior, later use, and security impact are unknown.

The hypothesized trigger is specifically a negative whole number arriving in the double-tagged representation. The source audit does not establish which user-visible computations retain that representation on a product build. No exploitability, memory corruption, or product impact is asserted.

## Expected source-control matrix

| Input representation/value | Source-predicted branch | Interpretation |
|---|---|---|
| TDouble `-1.0` or `-1024.0` | double round-trip true; upper bound true; fast path | Candidate condition; flows as negative int32 to allocation helper |
| TaggedInt `-1` | explicit `intLen >= 0` fails | Safe/fail-closed source control |
| TDouble `-0.5` | truncation round-trip differs | Slow path |
| TDouble `-0.0`, `0.0`, `1.0`, `1024.0` | round-trip and upper bound pass | Expected valid-length controls (`-0` semantic normalization unverified) |
| TDouble `1025.0` | upper bound fails | Slow path |
| TDouble NaN / positive or negative infinity | exact conversion/round-trip should fail or conversion behavior is implementation-specific | Must be verified; do not use as candidate evidence |

A negative exact integer is a source-level boundary case, not proof the runtime supplies `TDouble` for it. The tester was asked to verify the exact operations, both CommonStub and TypedHCR branches, NewByteArray size conversion, and possible downstream validation before any implementation is considered.

## Other inspected flows and counterevidence

- `NewObjectStubBuilder::NewTypedArray` uses `Int32Mul(elementSize, length)`, but its Slice/ToReversed/Map callers derive length from an existing TypedArray length; Filter's retained count is bounded by the source length. Source type and element size match. Ordinary ArrayBuffer allocation rejects lengths above `INT_MAX`; on-heap ByteArray paths are bounded by 4096 bytes. No reachable overflow in these calls was established.
- `NewTypedArrayFromCtor` is called by TypedArray `Of` after argument count is capped at three.
- `GetOffHeapBuffer` multiplies ByteArray element count by element size then casts to `int32`; on-heap ByteArray creation is gated by `MAX_ONHEAP_LENGTH = 512 * 8 = 4096`.
- `BuiltinsArrayBuffer::Slice`/`CloneArrayBuffer` clamp or rely on caller offset invariants; ordinary ArrayBuffer allocation caps byte length at `INT_MAX`, and Slice checks destination length and source detachment after species side effects. No concrete unsafe copy span was found.
- DataView compiler `GetTypedValue` uses a zero-extended INT64 length, unsigned `index + elementSize` comparison, and only then forms the buffer index. No additional candidate was found; its translation unit remains partial.

Relevant checked C1 file identities include `builtins_arraybuffer.cpp` blob `2aa22c58803df690a5a2b326451e02297dc5e2f6` / SHA-256 `4d388d997313cf7c900f1f0d54fbe826266845665424e32cc9dd4cdbaa62dcc9` (complete), `js_arraybuffer.cpp` blob `3c05650cfffa5ece7a8d00b546fea6a0b6107416` / SHA-256 `e7f0db160d3d58ba31854f30e2a2652b0b4a7daae092288b78f45702cc5aabad` (complete), `js_typed_array.cpp` blob `098c2a22cae3152af3a59063dda25e145f03bbd7` / SHA-256 `e67c0ce082885efb6fa5894f7a1998a41eb4cddfa2e381c8335497e10e2b9bbe` (complete), `typed_array_helper.cpp` blob `bcb422fe67f4e670adcca31fffd4da7e2b3b0b21` / SHA-256 `3c42388b716e82601cee4e43aedddc8ac709fe1363b0753c7efa24745380110d` (complete), and `object_factory.cpp` blob `52550d80288a1250529ed3d0f066c3302314f0d5` / SHA-256 `eb6e1227c93fd959af79553334a064ae0eb34828c30f0151993d0038295e0493` (complete). The `js_typed_array.h`, `byte_array.h`, `typed_array_helper.h`, `js_object.h`, compiler TypedArray builder, CommonStub and DataView stub files remain partial; their whole-file status is not upgraded by this local source review.

No C++ build, runtime execution, sanitizer run, or product configuration was available. Independent tester review was in progress when this scout report was prepared; incorporate its result before choosing a later implementation task.

