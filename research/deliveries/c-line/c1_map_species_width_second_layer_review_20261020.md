# C1 Map species-width candidate: second-layer source challenge

Date: 2026-10-20. This is a source-only challenge of the line-2733 candidate, not a runtime test, product assessment, or exploitability conclusion.

## Conclusion

The source candidate is technically plausible and survives this review as a conditional source-level width-mismatch candidate. In the pinned Map body, the receiver passed to `FastGetPropertyByIndex` is `thisValue`, while the explicit JSType argument is sampled from `newArray`. The pinned `NewTypedArray` fast path preserves the source type, but its slow path calls `TypedArraySpeciesCreate`; the same-commit species helper accepts any TypedArray result of sufficient length and checks Number-vs-BigInt ContentType, not exact element kind. The pinned read helper uses the supplied JSType to choose its load width and its visible index guard is against the source's logical element count. I found no same-commit source guard that bounds the selected load against the source view's byte length on the described Float32/Float64 path.

This proves a source-level mismatch is possible on the custom-species slow path, not that a specific execution reaches it or that the read crosses an allocator boundary. The production adapter replay documented in the candidate report remains partial and emits no finding because one required helper translation unit is only partially parsed. Thus the candidate is not currently an enabled production detector finding.

## Exact source reasoning

The reviewed target is Ark Runtime commit `a65a2853ccae13da167d9aa4720ab8b11ec16656`, tree `8781f036a3e7e04d8e0b34970d5f623b42875016`. The Map target file and its blob/SHA-256 are pinned in `c1_map_species_read_width_candidate_20261020.md` and the independent replay report.

At Map's setup, the source JSType is read from `thisValue`. `NewTypedArray(glue, thisValue, jsType, ...)` takes that source type for its default allocation. The fast path allocates an on-heap result using that type. If constructor/species guards fail, the slow path calls `TypedArraySpeciesCreate`. Map then reads the result's actual JSType from `newArray` and passes it at the source read site as `FastGetPropertyByIndex(glue, thisValue, ..., newArrayType)`.

In `FastGetPropertyByIndex`, the checked index is compared with `GetArrayLength(array)`. The value helper receives the same explicit `jsType` and chooses a type-specific byte offset/load. The Float64 case uses an eight-byte load at `index * 8 + offset`; the helper body contains no check of `offset + index * elementSize + elementSize <= source ByteLength`. Its runtime fallback forwards the explicit type argument to the runtime helper, so the fallback does not itself establish same-type use. The slow TypedArray species construction validates the result's TypedArray nature, requested length and ContentType. A Number-content source may therefore have a Float32/Float64 result, subject to user-defined species behavior.

## Challenge and boundaries

- **Species reachability is conditional.** The mismatch requires `NewTypedArray` to take its runtime slow path and the species constructor to return a wider Number-content TypedArray. Default species behavior follows the same-type fast path and does not produce the mismatch. No executed JS/runtime trace was part of this review.
- **View overread is distinct from native allocation overread.** The type-specific load can exceed the source view's byte extent. The source tree alone does not establish whether the backing allocation has padding, whether the extra bytes are accessible, whether a compiled backend emits the load as shown, or what observable value results. Treat memory-safety severity as unknown.
- **The candidate is existential, not a concrete type-pair verdict.** The model records that the species-produced type may differ; it does not prove a particular runtime species result is wider than its source. A source-level candidate is justified because a wider same-ContentType result is allowed; same-width, inverse-width and Number/BigInt control executions were not run.
- **No HClass/callback argument is needed.** This read occurs before the callback invocation in each loop iteration. The separate line-2747 callback/type-fact question remains independent.
- **Adapter integration remains blocked by parser status, not by counterevidence.** The direct analyzer seam supplied the exact species-width binding and reported the candidate, while the production adapter required complete parsing of its pinned helper set and retained unknown when `runtime_stubs.cpp` parsed partial. This review does not recommend weakening that gate without a separately reviewed, equally sound evidence scheme.

The candidate and independent replay reports correctly disclose the source/runtime/product boundary. Suggested next evidence, if development proceeds, is an isolated executable/runtime test that constructs a small Uint8 source with a custom Float32/Float64 species result and observes/ASan-checks the Map read, plus a same-width control. Until then: source candidate only; runtime behavior and product impact unknown.

