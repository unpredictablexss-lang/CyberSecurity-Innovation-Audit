# C1 Map species source-read width: independent source review and expected controls

Date: 2026-10-20. Scope: independent source/model review for the C-line TypedArray Map path. This report is not a runtime PoC or product-impact assessment.

## Pins and source locations

The analyzed Ark Runtime source is commit `a65a2853ccae13da167d9aa4720ab8b11ec16656`, tree `8781f036a3e7e04d8e0b34970d5f623b42875016`. Target `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp` is blob `68fb3b0adc4f9062889a861be51b7be90362e37a`, SHA-256 `76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c`.

In `Map`, source type is sampled from `thisValue` (~2701); `NewTypedArray` creates the destination at 2713; destination `newArrayType` is sampled at 2721. At 2733, `FastGetPropertyByIndex(glue, thisValue, index, newArrayType)` reads the source using the destination type. Callback is at 2739 and destination write with `newArrayType` is at 2747. The read mismatch is therefore before callback effects and distinct from the historical callback type-fact question at 2747.

`FastGetPropertyByIndex` checks detached state and logical `index < GetArrayLength(array)`, then selects `GetValueFromBuffer` based on the supplied JSType. Its Float64 branch uses an 8-byte element offset/load; no source-view byte-span validation is present in that path. The exact compiler data-pointer helper selects raw ByteArray/ArrayBuffer data without a length check. Runtime fallback `GetTypedArrayPropertyByIndex` forwards the explicit JSType; `JSTypedArray::FastGetPropertyByIndex` derives width from it and calls the ArrayBuffer getter, whose scalar templates dereference the requested bytes without a source-span bounds check.

Species creation follows `NewTypedArray` slow path through `TypedArraySpeciesCreate`/`TypedArrayCreate` when species protection does not hold. Result is validated as TypedArray and long enough, but compatibility is checked by Number-vs-BigInt ContentType, not exact element kind. Thus a same-Number-content species result may have a wider element size than its source. The relevant exact helper pins are recorded in the C1 model profile; expected dependency paths are new_object_stub_builder.cpp, typed_array_helper.cpp, runtime_stubs.cpp, js_typed_array.cpp, builtins_arraybuffer.cpp, and builtins_arraybuffer_stub_builder.cpp.

## Expected adversarial matrix

| Source / species result | Expected source-level disposition | Reason |
|---|---|---|
| Uint8 length 1 / Float64 length 1 | Candidate at Map read 2733 | Logical index 0 passes, but the supplied result type selects an 8-byte read from a 1-byte source view. |
| Uint8 length 1 / Float32 length 1 | Candidate at 2733 | 4-byte read exceeds the 1-byte view span. |
| Uint8 / Uint8, or equal-width signedness variant | No wider-span candidate | Element width does not exceed source width; other semantic concerns are outside this candidate. |
| Float64 source / Uint8 result | No wider-span candidate | Read width is narrower than source element width. |
| BigInt source / Number species or reverse | No width candidate; species validation rejects before loop | TypedArray species helper enforces ContentType equality. |
| Wider result at final valid source index `N-1` | Candidate | Logical bound allows it; requested byte span can exceed source view bytes. |
| `index == source length` | No read/candidate | The helper's logical index check rejects it. |
| Missing/mismatched allocator, read helper, or raw-load binding; malformed signature | Unknown, never candidate | Source/effect boundary is not established. |
| Unrelated function / no Map species-read flow | No candidate (or existing unknown) | Candidate is exact-flow scoped. |

An escaped species result and callback-visible prototype/HClass changes are relevant to the separate line-2747 question, not required for the line-2733 read mismatch. HClass clone/prototype transitions copy `GetObjectType()`, so shape/prototype identity change alone is not evidence of JSType change. No claim is made that the source-level raw read is reachable in a compiled product configuration or that it yields a practical exploit.

## Analyzer-version discrepancy

The prior historical analyzer checkout at `463f6e3b9e180aa1d39fe6eb49079c66de046e31` produced a Map `unknown/type_fact_invalidated_by_call` observation at 2747. Current baseline `fbb537a39183b719bd587e0dd4a5ba83c6d85925`, with both `RuntimeTypeModel()` and `c_line_static_model()`, instead stops the Map walk at 2733 with `effectful_helper_contract:...FastGetPropertyByIndex`; the partial parse has 13 issues and 12 unknowns. This is analyzer-version drift, not a target-source hash discrepancy. The 2747 historical observation is not the basis for the 2733 source-read candidate.

## Replay status

I replayed exact target bytes from the pinned source using `analyze_unit(..., model=c_line_static_model(), research_partial=True)` on the working tree based at analyzer commit `6c01fa4fdcfb7c604c5ffc0e6c339041314b4feb`, including the developer's then-uncommitted assignment-RHS traversal fix. The direct C1-bound analysis emitted a candidate at line 2733 (`species_result_type_used_for_source_element_read_width`), followed by an unknown at the same line on a later loop iteration (`species_source_read_type_invalidated`) and an unknown at line 2747 (`type_fact_invalidated_by_call`). The later same-line unknown path includes the callback at 2739 and a loop-back to the read; it is a separate state, not a duplicate graph instruction. The candidate records source `thisValue`, result type token sampled at 2721, and a possible type divergence after species creation. `RuntimeTypeModel()` / unbound mode retained unknown at 2733 (`effectful_helper_contract...FastGetPropertyByIndex`). Both runs remained `limited` / `partial` for the translation unit.

This replay directly supplied `species_read_width_bound=True`; it did not exercise the adapter's exact six-dependency gate. Therefore positive adapter activation and wrong/missing-pin fail-closed behavior remain unverified here. The semantic same-width, inverse-width, and cross-ContentType controls are supported by source inspection, not executed as detector fixtures. No runtime/product conclusion is made.
