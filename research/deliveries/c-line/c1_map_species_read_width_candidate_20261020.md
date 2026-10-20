# C1 Map species-result/source-read width candidate (2026-10-20)

This addendum records a distinct issue from the earlier line-2747 callback type-fact question in `c1_map_type_fact_effect_review_20261020.md`. It concerns the source element read at line 2733 and does not establish compiled/runtime impact or product behavior.

## Exact source evidence

Target: `openharmony/arkcompiler_ets_runtime`, commit `a65a2853ccae13da167d9aa4720ab8b11ec16656`, tree `8781f036a3e7e04d8e0b34970d5f623b42875016`, `ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp`, blob `68fb3b0adc4f9062889a861be51b7be90362e37a`, SHA-256 `76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c`.

At Map line 2713, `NewTypedArray` constructs the destination; line 2721 samples its actual JSType into `newArrayType`; line 2733 calls `FastGetPropertyByIndex(glue, thisValue, index, newArrayType)`. The helper reads the source `thisValue` but uses the destination's element kind to calculate the source load width. Its visible guards check detachment and logical source index/length, then `GetValueFromBuffer` chooses the byte offset and load width from the supplied JSType. The exact inline Float64 path computes `index * 8 + offset` and loads 8 bytes; no source byte-span check appears in this helper. The runtime fallback forwards the same JSType into `JSTypedArray::FastGetPropertyByIndex`, which likewise derives the span from that type and reaches raw typed loads without a source byte-span check.

The exact same-commit species helper validates a TypedArray result and length, then checks only Number-versus-BigInt content type. It permits different element kinds within a content type. Thus a one-byte Uint8 source and a valid Float64 species result can reach the loop with a destination type whose width exceeds the source element width. At the final in-range source index, the logical-length guard still passes while the computed read span can extend past the source view's byte length. This is a source-level width-mismatch candidate; the actual runtime/compiler consequence remains unverified.

## Scope of the implementation

The model now recognizes only the exact pinned C1 target and its six pinned same-commit evidence files. The adapter enables the summary only after validating repository, commit, path, target blob/SHA, the complete expected dependency path set, and each dependency's blob/SHA and complete parse status. Missing or mismatched evidence leaves the generic helper effect unknown. The helper-effect exception is additionally limited to the Map call with the exact unqualified helper, arity, and arguments `glue, thisValue, TruncInt64ToInt32(*i), newArrayType`; candidate generation requires a distinct source object from the sampled destination-type origin. Generic analysis defaults to unbound. The first implementation commit is `89872899a463b009883db0780092dc6c23e49637`; follow-up commit `20be381cea1e65342ea564de7d65c80b1dc993e4` corrects this exact AST argument binding and adds this report.

The separate line-2747 callback issue remains unresolved independently. Species escape is possible, but ordinary HClass/prototype transitions observed in the pinned tree preserve JSType; shape change alone is not evidence for a line-2747 candidate.

## Boundary matrix

| Case | Expected disposition |
|---|---|
| Exact bound Map source read, same-content wider species (Uint8→Float32/Float64) | Source-level width-mismatch candidate at line 2733; translation unit remains partial |
| Same-width source/result | No wider-read candidate |
| Wider source→narrower result | No wider-read candidate |
| Number↔BigInt content mismatch | Species validation rejects before the loop; no mismatch candidate |
| Final in-range index with wider result element type | Candidate remains possible; logical index check does not bound byte span |
| Index equal to source logical length | Helper rejects it; no candidate for that index |
| Missing/wrong target pin, any missing/mutated dependency, malformed signature, or generic model | Preserve unknown helper effects; no candidate |
| Line-2747 callback changes result HClass/prototype only | Separate question; no candidate from HClass identity alone |

No security, safety, exploitability, compiled behavior, or product claim is made. The source translation unit's parse-partial status and existing limitations remain in force.
