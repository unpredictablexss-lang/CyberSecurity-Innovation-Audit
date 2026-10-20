# Float32Array negative-TDouble static candidate: final second-layer review

Date: 2026-10-20. Reviewed developer implementation `46fdb5887c49a552b249fb20805025ba6316d8d0`, independent same-SHA replay `6d41c4746b41c21af9139d2853acc1d0c9189ffa`, and the exact-source scout, runtime inventory, and property-load review reports. No detector implementation was changed in this review.

## Disposition

**Accept, with narrow source-candidate wording.** At exact Ark Runtime source commit `a65a2853ccae13da167d9aa4720ab8b11ec16656`, the Float32Array CommonStub and TypedHCR paths each accept an exact integral TDouble using a truncation-to-int32 round trip and an upper-only `MAX_GAP` predicate. Their tagged-int paths separately retain an explicit `>= 0` check. For representable `TDouble(-1.0)`, the conversion and round trip yield `-1`, so the missing negative check is source-visible in both paths. The exact helper then multiplies the signed `int32` size and calls `NewByteArray`. This supports one candidate for a constructor length-guard gap; the candidate does not prove a completed constructor call, memory-safety impact, or affected product.

The 32-bit follow-on remains conditional but has a concrete source path. If the negative-double fast path completes and the 16-byte allocation succeeds, `NewByteArray`'s wrapped 32-bit size calculation yields a backing object ending at its data offset, and the initializer's `[16,16)` interval is empty. The view and backing metadata nevertheless contain uint32 `0xffffffff` length and `0xfffffffc` view byte length. The `LoadValueMiss` dispatch's early ordinary-get check does not consume this Float32Array path: `JSHClass::HasOrdinaryGet()` is true only for special containers, module namespaces, and BigInt64Array, so ordinary Float32Array reaches the following TypedArray dispatch. For an indexed IC miss on key `"0"`, `LoadTypedArrayValueMiss` checks `IsValidIntegerIndex`; that helper sees uint32 length `0xffffffff`, rejects no detached/integer/negative-zero condition for zero, and does not compare ByteLength. The IC-enabled branch passes index 0 to the uint32 C++ getter, which chooses Float32 from the object HClass and reads four bytes from ByteArray data offset 16. The ByteArray detachment check returns false, and the raw buffer helper has no data-span guard. IC-disabled generic `[[Get]]` also reaches a uint32-length integer-indexed path. This is a conditional source-level out-of-allocation read hypothesis, not an executed OOB result. The inline CommonStub getter's signed guard remains a separate path and rejects index 0 for the malformed negative int32 length; it does not negate the C++ IC-miss path.

## Detector and replay assessment

The implementation's source binding is appropriately narrow: exact repository, source commit, `light-ast` Git-object provenance, three immutable path/blob/SHA rows, focused function slices, and the exact CommonStub/TypedHCR/helper shape. It emits only one `unassessed` candidate at `common_stubs.cpp:228`; it retains `partial`/`blocked` coverage because the CommonStub translation unit has 13 parser issues, even though the reviewed source slice parses cleanly. Wrong commit, missing helper, and model-pin tampering fail closed. The independent same-implementation-SHA replay confirms the exact positive gives one candidate and the wrong-commit/missing-helper cases give no candidate while remaining blocked/not-analyzed. Unit and Ark detector suite results recorded by the tester do not execute Ark Runtime.

The candidate report correctly limits its obligations: compiled dispatch, argument tag at the call site, allocator result, metadata observability, and memory effect remain unknown. In particular, do not title or surface the finding as an out-of-bounds read. Keep the 32-bit ordinary-property path as a second-layer follow-up hypothesis only. A 64-bit allocation request is roughly 16 GiB plus header/alignment and may fail or trigger memory pressure; the local report has no 64-bit runtime result either.

## Exact evidence pins

Candidate source: `openharmony/arkcompiler_ets_runtime`, commit `a65a2853ccae13da167d9aa4720ab8b11ec16656`, tree `8781f036a3e7e04d8e0b34970d5f623b42875016`.

| Source path | Blob | SHA-256 |
|---|---|---|
| `ecmascript/compiler/common_stubs.cpp` | `6267f2f27a98a298b1190e327abbfa2bd58203f8` | `5a401580e666596fcf2ea89a8dc0321009b53ef5320b20edc59d37781d852212` |
| `ecmascript/compiler/typed_hcr_lowering.cpp` | `1ad4e329a226fc9941db30fa7a10a6562f58f68d` | `acd4ed88bb4ba5d327d5628dc45b7b89685a9c425c5849891cbf2544e8534a0c` |
| `ecmascript/compiler/new_object_stub_builder.cpp` | `991ac5ac034a1a027e3200787ec25c55b3f15b69` | `3159eee6989838659438af89353dfd37a890c259f60c3af0195110e016a411e0` |
| `ecmascript/ic/ic_runtime.cpp` | `b537f58ae2f00286cbbef456d0a33cdfe382f896` | `e0aa8acddc21b361a6fdc6d70782d2ebc4f15464ffd77d37d193ca1bc83dc0cf` |
| `ecmascript/js_typed_array.cpp` | `098c2a22cae3152af3a59063dda25e145f03bbd7` | `e67c0ce082885efb6fa5894f7a1998a41eb4cddfa2e381c8335497e10e2b9bbe` |
| `ecmascript/builtins/builtins_arraybuffer.cpp` | `2aa22c58803df690a5a2b326451e02297dc5e2f6` | `4d388d997313cf7c900f1f0d54fbe826266845665424e32cc9dd4cdbaa62dcc9` |
| `ecmascript/js_hclass.h` | `fca61941b181d1796d485e387054221d6f136337` | `36d38fd0d12b05c21069a663418b569063e96912f6758b9611b832a78477d4e3` |
| `ecmascript/byte_array.h` | `82780d249f5170b4ec5bf0474e71fd1cb110b67a` | `4acb3d1f596efa3e9d7d943ea7c423fe13c7077c512e251ac994a72426d92ddc` |

The implementation SHA is `46fdb5887c49a552b249fb20805025ba6316d8d0`. The independent tester states that this exact SHA was checked out clean before the replay. It observed one candidate at `common_stubs.cpp:228` for the exact a65 positive, zero for wrong commit and missing helper with blocked/not-analyzed status, 5 focused tests passing, and 198 Ark detector tests passing with 3 skipped. Its Ark Runtime build inventory found no usable executable, configured build tree, or toolchain; all constructor/control/32-bit/64-bit/ASan cases are `not_run`.

## Remaining unknowns

`Math.ceil(-1.1)` is source-plausible as a route to a TDouble `-1.0` because `CeilInternal` returns `GetTaggedDouble`, but actual call-site tagging and constructor stub selection have not been observed in a built Ark VM. No 32-bit build was available, so wrapped allocation and the ordinary IC-miss raw read remain source-only. No fixed-source CLI run under a separately pinned fixed commit, mutated-helper Git-object case, mutated target hash case, or Ark Runtime execution was completed in the independent replay. These limits do not invalidate the narrow missing-guard candidate; they preclude elevating it to a runtime or product finding.

The smallest decisive next experiment is an isolated 32-bit Ark Runtime/ASan build with instrumentation at the constructor fast-path branch, `NewByteArray` allocation and initialization interval, and ordinary `LoadTypedArrayValueMiss` dispatch. Compare `new Float32Array(Math.ceil(-1.1)); a[0]` against tagged-int `new Float32Array(-1)` and positive integral-TDouble controls. Retain runtime outcomes as unknown until executed.

