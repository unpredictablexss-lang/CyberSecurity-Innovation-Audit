# C1 Map result-type fact across callback effect review (2026-10-20)

## Scope and exact binding

This review addresses only the `BuiltinsTypedArrayStubBuilder::Map` partial-analysis observation at source line 2747. It does not infer product behavior, runtime exploitability, safety, or accuracy.

The assigned Ark Runtime target is `openharmony/arkcompiler_ets_runtime` commit `a65a2853ccae13da167d9aa4720ab8b11ec16656`, tree `8781f036a3e7e04d8e0b34970d5f623b42875016`, path `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp`, blob `68fb3b0adc4f9062889a861be51b7be90362e37a`, SHA-256 `76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c`. The exact commit and its helper tree were verified from `D:\openHarmonyScanner\tmp\c-line-ark-history-full-snapshots-20261018.git`.

| Same-commit source path | Git blob | SHA-256 |
|---|---|---|
| `ecmascript/compiler/new_object_stub_builder.cpp` | `991ac5ac034a1a027e3200787ec25c55b3f15b69` | `3159eee6989838659438af89353dfd37a890c259f60c3af0195110e016a411e0` |
| `ecmascript/base/typed_array_helper.cpp` | `bcb422fe67f4e670adcca31fffd4da7e2b3b0b21` | `3c42388b716e82601cee4e43aedddc8ac709fe1363b0753c7efa24745380110d` |
| `ecmascript/js_hclass.cpp` | `241359029874d0f32ace5bc3ca9685dc3a3e1840` | `b81a9d06a91d3aa20d552738150c6a9e0c622cc2572079ab31ab098c3579d261` |
| `ecmascript/js_hclass.h` | `fca61941b181d1796d485e387054221d6f136337` | `36d38fd0d12b05c21069a663418b569063e96912f6758b9611b832a78477d4e3` |

## Observed flow and current model result

In the exact target, `Map` calls `NewTypedArray(glue, thisValue, jsType, ...)` at line 2713, samples `GetObjectType(LoadHClass(glue, newArray))` at line 2721, dispatches the user callback at line 2739, and passes that sampled `newArrayType` to `FastSetPropertyByIndex` at line 2747.

There is a material analyzer-version difference. At isolated analyzer/report HEAD `463f6e3` (the tester independently replayed both `RuntimeTypeModel()` and `c_line_static_model()`), exact Git-show bytes produced one Map sink observation at line 2747 with reason `type_fact_invalidated_by_call`, target `new:111634`, token sampled at line 2721, and effect sites including `NewTypedArray` at 2713 and `JSCallDispatch` at 2739. The older C1 note `c1_partial_state_root_cause_20261020.md` is valid for that analyzer state.

On current planning HEAD `fbb537a39183b719bd587e0dd4a5ba83c6d85925`, I replayed `analyze_unit` on the exact Git-show bytes (`SHA-256 764185...bd3c`, parse `partial`, 13 issues) with both `RuntimeTypeModel()` and registered `c_line_static_model()`. Each returned file outcome `partial` and 12 unknown observations. The Map-path unknown is at line 2733 with reason `effectful_helper_contract:panda::ecmascript::kungfu::BuiltinsTypedArrayStubBuilder::FastGetPropertyByIndex:eb11a232c119`; neither current model produced a line-2747 `type_fact_invalidated_by_call` observation. Thus the current engine's helper-effect limit stops this trace before the callback/sink question. The old sink-level result is reproducible historical evidence, not the current replay baseline.

The helper reason is understandable from the exact `FastGetPropertyByIndex` body: it can call `GetTypedArrayPropertyByIndex` at runtime on detached/non-number paths. That helper reads `thisValue`, whereas the destination type sample belongs to `newArray`; no local proof ties this source read to mutation of `newArray`'s type. However the current helper-contract machinery treats the call as effectful and conservatively stops the local proof. This is a detector/model limitation, not a finding that the Map sink's type is wrong.

The sample is taken after `NewTypedArray` returns. The same-commit helper calls `TypedArraySpeciesCreate` on its slow path; `TypedArrayCreate` validates that the constructed result is a TypedArray and checks its length, while `TypedArraySpeciesCreate` requires matching Number-vs-BigInt content type. It may therefore return a different element kind within the same content type, but line 2721 samples the returned object's actual JSType, so no pre-creation input type is reused. This removes one stale-type explanation, but does not prove the sample remains valid across the callback.

## Escape and mutation assessment

The result is not passed as an explicit callback argument: the callback receives the source value, index, and `thisValue`. However, non-escape cannot be assumed. The exact helper's species/runtime fallback calls `TypedArraySpeciesCreate`, which calls `TypedArrayCreate`, then `JSFunction::Construct`; a custom species constructor can retain the object it constructs, making it observable to a later callback through user state. The same-tree path therefore supports a feasible result escape; it does not establish that every call takes the species path.

An escaped alias can plausibly undergo prototype or shape changes during the callback. The exact `JSHClass::Clone` copies the existing JSType, and prototype/property transition paths inspected here use `Clone`, supporting that HClass/prototype changes alone preserve this discriminator. `CloneWithNewSizeAndType` is an explicit API that can change JSType, but this review found no callback-reachable path that reclassifies an existing TypedArray through it. This supports rejecting a candidate based only on changed HClass identity or shape. Still, the current analyzer does not model the runtime callback as a bounded property-preserving effect, and the sink has both inline and runtime paths that consume the cached type. A distinct-type `candidate` would require evidence of a concrete sink-relevant type change or mismatch; none is present.

## Disposition

Keep the current Map-path `unknown` (`effectful_helper_contract` at line 2733) and do not emit a candidate. The old sink-level `type_fact_invalidated_by_call` result is not reproduced under current model code. Arbitrary callback execution plus feasible result escape means non-escape cannot justify preserving the fact. Same-tree evidence shows ordinary HClass clone/prototype/property transitions preserve JSType; this narrows the uncertainty but does not make the current model's earlier helper-effect unknown a false result. A useful relaxation would need an explicitly bounded effect summary for exact `FastGetPropertyByIndex`/runtime helper calls and a callback-effect invariant covering the target object's JSType, with tests for escaped results and mutation. No such model rule is introduced here.

This conclusion is about the detector's evidence discipline, not a claim that the runtime type actually changes. The translation unit remains `partial` with its existing parser/model limitations; this review does not upgrade coverage or claim a safety result.

## Tester boundary matrix

The independent tester was given these expected dispositions before finalization:

| Boundary | Expected result |
|---|---|
| Historical exact-source replay at analyzer HEAD `463f6e3` with both models | One Map sink observation at line 2747, `unknown/type_fact_invalidated_by_call`; target `new:111634`, token line 2721, effect sites include `NewTypedArray` and `JSCallDispatch` |
| Current exact-source replay at planning HEAD `fbb537a` with both models | 12 unknown observations; Map path stops at line 2733 with `effectful_helper_contract:...FastGetPropertyByIndex`; no current line-2747 type-fact observation |
| Exact Map allocation → post-creation type sample → callback → property-store sink, if earlier helper effect is bounded | `unknown` until callback-effect/JSType preservation is proved; no candidate |
| Species-selected different valid TypedArray kind | Sample is after creation; no stale input-type claim; callback effect remains unknown absent model proof |
| Species constructor retains result alias; callback changes its prototype/shape | Treat as escaped; exact ordinary HClass clone transitions preserve JSType; HClass/shape difference alone is not a candidate |
| Concrete sink-relevant JSType change across callback | Candidate only with direct evidence linking changed category to the sink behavior; none established here |
| Same-type creator followed by arbitrary callback | Separate control; callback invalidation remains unless independently proven |
| Missing/ambiguous creator, sink, or malformed signature | Unknown; never infer a candidate from unresolved bindings |

## Remaining proof obligations

1. Refine exact helper effects so the `FastGetPropertyByIndex` call at line 2733 does not erase unrelated destination facts without a reasoned alias/effect relation; retain unknown if its runtime fallback cannot be bounded.
2. Establish whether any JS callback-reachable operation can change a retained TypedArray's JSType category, distinct from changing HClass identity/prototype/shape.
3. Establish whether `FastSetPropertyByIndex`'s cached type is required to match the receiver's post-callback type, including its runtime slow path.
4. Only if these establish a sound invariant, add a model exception limited to the exact creator-result token and this sink; otherwise retain unknown behavior.

No implementation change was justified by the available exact-boundary evidence.
