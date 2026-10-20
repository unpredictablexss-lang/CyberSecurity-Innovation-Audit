# TypedArray copy/mutation source scout — 2026-10-20

## Outcome

**One conditional, high-signal source candidate selected:** `%TypedArray%.prototype.set(arrayLike, offset)` can overflow the unsigned element-range sum, then narrow/wrap the computed byte index and write before a nonzero-offset target view. This is a source-level candidate for cross-view backing-buffer corruption, not a confirmed runtime or product vulnerability. It is outside the already-closed Float32 negative-double and length-narrowing rules; no production code was changed.

## Identity and provenance

- Repository: `D:\OpenHarmony807\repos\arkcompiler_ets_runtime`
- Revision: `a65a2853ccae13da167d9aa4720ab8b11ec16656` (`master`)
- Checkout clean; exact tree `8781f036a3e7e04d8e0b34970d5f623b42875016`; individual blob OIDs checked.
- Pinned source/dependency blobs:

| Path | Git blob |
|---|---|
| `ecmascript/builtins/builtins_typedarray.cpp` | `b291181c949c7038b7030a216f5bdc0e7474a1c2` |
| `ecmascript/builtins/builtins_typedarray.h` | `0fc27c213e1ea80d93e1e3807eec11baf2634832` |
| `ecmascript/builtins/builtins_array.cpp` | `641b7785acd6cf73abcd404dcdcf0727c92c1fda` |
| `ecmascript/base/typed_array_helper.cpp` | `bcb422fe67f4e670adcca31fffd4da7e2b3b0b21` |
| `ecmascript/base/typed_array_helper.h` | `92b73cdcf4b4e05453cc21e24f7e9364dd6949ce` |
| `ecmascript/js_typed_array.cpp` | `098c2a22cae3152af3a59063dda25e145f03bbd7` |
| `ecmascript/js_typed_array.h` | `d59bc3138542afa22bfe2a2f42f5fa756a6dae1a` |
| `ecmascript/builtins/builtins_arraybuffer.cpp` | `2aa22c58803df690a5b2a326451e02297dc5e2f6` |
| `ecmascript/builtins/builtins_arraybuffer.h` | `c938b4263bdae62c1418dc8ca159b2ba8bc0a493` |

The checkout is a shallow source snapshot without parent history, so no parent/fixed patch comparison is claimed.

## Candidate trace

At `builtins_typedarray.cpp:1157-1179`, `offset` is converted with `ToInteger`; finite nonnegative values are cast to `uint64_t` without an upper-bound check. The array-like branch reads `srcLen` as `uint64_t` (`1217-1226`) and checks `srcLen + targetOffset > targetLength` (`1227-1230`) without guarding unsigned addition overflow. It then asserts the byte offset fits, but the assertion expression itself uses `uint64_t` arithmetic and can wrap (`1232-1235`). The actual `targetByteIndex` and `limit` are `uint32_t` (`1235-1241`); `SetValueInBuffer` ultimately writes through `block + byteIndex` (`builtins_arraybuffer.cpp:401-406, 722-749`) and does not receive the TypedArray view's length for a separate check.

Concrete source-derived trigger arithmetic for `Uint8Array`:

- Backing `ArrayBuffer`: 6145 bytes. Target view: byteOffset 4096, length 2049.
- Array-like source: length 2049 with numeric values at indices 0..2048.
- Offset argument: exact finite integer `2^64 - 2048` (`18446744073709549568`, exactly representable as binary64 and within `uint64_t`).
- `srcLen + targetOffset` wraps modulo `2^64` to `1`, so the range check accepts it against `targetLength=2049`.
- The widened assertion sum `targetOffset + targetByteOffset` wraps to `2048`, which is `<= UINT32_MAX`.
- `uint32_t(targetOffset) + targetByteOffset` wraps to `2048`; `limit = 2048 + 2049 = 4097`.
- The loop therefore performs 2049 byte writes at backing-buffer byte indices 2048..4096. The target view begins at 4096, so 2048 writes modify bytes before the target view, potentially corrupting another view/object using the same backing store. These indices are still inside the 6145-byte backing allocation; the source finding is cross-view corruption, not a proven allocation-boundary OOB.

The path requires the ordinary array-like overload (`!argArray->IsTypedArray()`), so the stable-array fast path must not consume the chosen source; an ordinary array-like object with a `length` and indexed properties can exercise the general loop. The loop checks buffer detachment but that does not validate the computed index against the target view.

## Counterevidence, controls, and unknowns

- `srcLen` must be large enough to overflow `targetOffset + srcLen`; this is an extreme but representable offset/length combination. Reachability, runtime numeric representation, and engine behavior are not executed.
- The exact `uint64_t` to `uint32_t` wrap and `uint32_t` end-loop arithmetic are explicit source operations; no architecture-specific out-of-range floating-to-integer conversion is needed because the selected double is representable in `uint64_t`.
- The candidate may be prevented or altered by details in argument handling, array-like classification, build configuration, or deeper buffer semantics; these require runtime validation. No claim about shipped products or exploitability.
- Safe/fixed controls for follow-up: small in-range offsets; offset `targetLength - srcLen`; offset `targetLength - srcLen + 1` (must throw); same source with a corrected overflow-safe check (`targetOffset > targetLength || srcLen > targetLength-targetOffset`); zero byteOffset view; nonzero byteOffset with ordinary array-like vs stable-array source; wrong commit/blob; missing or mutated `SetValueInBuffer`/method helper.
- `copyWithin`, `fill`, `reverse`, and `sort` were checked as counterevidence and yielded no separate candidate: `copyWithin` computes overlapping indices and uses property get/set; `fill` revalidates after coercion and clamps byte end to current length; `reverse` swaps by indexed properties; `sort` checks detach after comparator callback and writes through indexed property setters. No species-copy candidate was found in the inspected API surface; `subarray` is a view creation path.

Runtime build, isolated PoC, ASan, compiler/runtime dispatch, parser coverage for these functions, product build/profile, and impact are all `not_run` or `unknown`. Do not treat source arithmetic as a dynamic validation result.

## Scanner and parser baseline

Current OHScanner (`model.py`/`detector.py`) has typed-array rules for compiler store type-origin, allocation exception protection, buffer-size multiplication, receiver type guards, and signed-to-unsigned allocation-length narrowing. It has no registered rule for the builtins `set(arrayLike, offset)` range/narrowing path, so current expected scanner result is **no modeled finding**, not a proven safe result. A C++ parser/direct source analyzer run over the pinned builtin/helper files was **not_run**; per-file parser/dependency status is unknown. A future implementation must fail closed when any method/helper blob is absent, mismatched, mutated, or incomplete.

## Structured follow-up prompts

### Developer

ROLE=Ark Runtime source-bound detector developer. INPUT=this report; exact Ark Runtime revision `a65a2853ccae13da167d9aa4720ab8b11ec16656`; pinned set, buffer-write helper and declaration blobs above. GOAL=emit at most one narrow candidate for the `set(arrayLike, offset)` unsigned range-sum/byte-index wrap path. STEPS=verify clean revision/tree/blob/SHA; establish parser completeness for the exact method and `SetValueInBuffer`; model the ordinary array-like route only; add a positive trigger using the source-derived arithmetic; add in-range, one-past-range/fixed-check, zero-view-offset, stable-array fast-path, unrelated method, wrong-commit, missing-helper and mutated-helper controls; keep partial/unknown when proof is incomplete. OUTPUT=small detector/test/report change plus expected-result matrix for independent replay. STOP=one precise candidate on exact source with controls, or evidence-based no-go. NEVER=edit Ark Runtime source, duplicate closed length/Float32/DataView/receiver/C1 work, claim runtime/product impact or formal precision, equate no finding with safety, or implement the second-layer LLM.

### Independent tester

ROLE=independent Ark Runtime static-detector tester. INPUT=this report, source pins, and developer commit/matrix if implementation proceeds. GOAL=challenge trigger arithmetic, route selection, and fail-closed identity behavior without editing production detector/model code. STEPS=independently verify exact source blobs and parser states; reproduce the expected byte indices with an independent calculation; replay positive and safe/fixed controls on the developer SHA; test wrong commit/blob and missing/mutated method/helper; return any concrete counterexample to developer. OUTPUT=same-SHA independent report with commands/results and explicit partial/blocked/not_run. STOP=one independent determination; if no developer change is made, record not_run rather than inventing a test completion. NEVER=claim exploitability/product impact from static output, claim safety from a zero finding, modify production binding, or broaden into excluded scopes.
