# TypedArray `set(arrayLike, offset)` final independent review

Date: 2026-10-20. Reviewed developer implementation `f0ecebbe2d8b7b5318e3258b39088e03943a32ac`, independent replay report `typedarray_set_arraylike_independent_replay_20261020.md`, and the pinned Ark Runtime source. The replay was run from the exact implementation checkout; current task-tree HEAD `5d0bf2d87` differs only in task-tree JSON, with no production-code/test diff from the implementation SHA.

## Disposition

**Accept as a narrow, conditional source candidate.** On Ark Runtime source commit `a65a2853ccae13da167d9aa4720ab8b11ec16656`, the ordinary array-like overload of `BuiltinsTypedArray::Set` checks `srcLen + targetOffset` in `uint64_t` without guarding addition overflow, then computes a byte index including `targetByteOffset` and narrows it to `uint32_t`. The write loop sends that byte index to the backing-buffer writer, where the Uint8 path reaches a raw indexed byte store. The source does not show a separate target-view length check on that route.

For the stated Uint8Array arithmetic (`srcLen=2049`, `targetOffset=2^64-2048`, view byte offset 4096, backing length 6145), the range sum wraps to 1; the byte start and loop limit are 2048 and 4097. Thus 2048 candidate writes precede the target view, while every predicted write remains within the 6145-byte backing allocation. The finding is appropriately described as a **possible cross-view backing-store overwrite**, conditional on successful argument conversion and execution of the ordinary array-like path. It is not evidence of allocation-boundary OOB, runtime exploitability, or product impact.

The array-like route is source-plausible: a non-typed ordinary object with a `length` property and indexed numeric values avoids the stable-JS-array fast return and enters the generic loop. A stable packed JS Array may instead use `FastCopyFromArrayToTypedArray`, so it must not be used as the sole trigger. A nonzero target byte offset is necessary for the before-view interpretation; a sibling view over those bytes is needed to call the consequence cross-view corruption.

## Implementation and replay assessment

The candidate is localized at `builtins_typedarray.cpp:1227` and bound to the exact repository, source commit, target/helper blobs and SHA-256 values, Git-object provenance, and `light-ast` profile. Its inspected Set slice spans lines 1134–1379 and includes both overload branches; the rule's structural evidence specifically requires the ordinary array-like branch, its stable-array fast-path distinction, wrapped range check, narrowed byte index, loop, and sink call. This is a whole-method source region with the observation located at the range guard, not a claim that every statement in the method is vulnerable.

The declaration header is correctly pinned as `partial` with 33 parser issues; it is not promoted to complete. The exact target and write-helper translation units and relevant slices parse completely, but the result remains partial/blocked due to the header. Independent replay on implementation SHA `f0ecebbe2d8b7b5318e3258b39088e03943a32ac` observed one unassessed candidate for the exact source; missing sink helper and wrong repository each yielded zero findings while remaining blocked. Focused tests passed 12 cases, including fixed subtraction shape, arithmetic controls, stable-array-only, unrelated sink, mutated helper, and wrong provenance. The alternate historical source commit was unavailable, so no wrong-commit M2 replay was performed. These static checks support the narrow candidate and fail-closed behavior in the tested cases; they do not validate runtime behavior.

## Exact source pins and limits

Ark Runtime repository identity: `openharmony/arkcompiler_ets_runtime`; commit `a65a2853ccae13da167d9aa4720ab8b11ec16656`; tree `8781f036a3e7e04d8e0b34970d5f623b42875016`.

| Source path | Blob | SHA-256 | Parse |
|---|---|---|---|
| `ecmascript/builtins/builtins_typedarray.cpp` | `0fc27c213e1ea80d93e1e3807eec11baf2634832` | `14507ac872dc34a6c20b6f448678466f119de94a4ed1de6d91e269640936c81c` | complete |
| `ecmascript/builtins/builtins_arraybuffer.cpp` | `2aa22c58803df690a5a2b326451e02297dc5e2f6` | `4d388d997313cf7c900f1f0d54fbe826266845665424e32cc9dd4cdbaa62dcc9` | complete |
| `ecmascript/builtins/builtins_typedarray.h` | `b291181c949c7038b7030a216f5bdc0e7474a1c2` | `651d426c00c1d8bc6503c1d717decf42b28c61c57336e9418ad422604a6a1be7` | partial, 33 issues |

The scout's initial `.cpp` and `.h` identities were transposed; the independent baseline and replay confirm the corrected pins above. No Ark Runtime build, runtime PoC, ASan run, architecture-specific execution, product-profile binding, or impact test was performed. Runtime numeric conversion/dispatch and actual writes remain `not_run`/`unknown`. Keep the result candidate-only and blocked/partial until those independent execution conditions are tested; do not report a confirmed vulnerability or OOB.
