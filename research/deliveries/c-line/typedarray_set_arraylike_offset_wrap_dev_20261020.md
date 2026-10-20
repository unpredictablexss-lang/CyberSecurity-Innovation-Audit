# TypedArray `set(arrayLike, offset)` candidate implementation — 2026-10-20

## Result

Added one exact-source, candidate-only rule for the ordinary array-like branch of `%TypedArray%.prototype.set`. On the pinned Ark Runtime source it reports one candidate at `ecmascript/builtins/builtins_typedarray.cpp:1227`: the `uint64_t` `srcLen + targetOffset` range check can wrap before the byte index is narrowed to `uint32_t`, and the narrowed index reaches the backing-store writer without a TypedArray-view bound check. The source-derived trigger predicts a **cross-view backing-store write**; all predicted write indices remain inside the allocated ArrayBuffer. This does not claim an allocation-boundary out-of-bounds access, runtime vulnerability, or product impact.

## Provenance and parser evidence

Scanner workspace base: branch `codex/c-line-parallel-plan-20261020`, prior HEAD `6ffe9211ed839a241f94b0fe8ff93af126bb846a`. Upstream component checkout `D:\OpenHarmony807\repos\arkcompiler_ets_runtime` was clean at `a65a2853ccae13da167d9aa4720ab8b11ec16656`, tree `8781f036a3e7e04d8e0b34970d5f623b42875016`.

Exact model pins used by the rule:

| Role | Path | Git blob | SHA-256 | Parse state |
|---|---|---|---|---|
| Target | `ecmascript/builtins/builtins_typedarray.cpp` | `0fc27c213e1ea80d93e1e3807eec11baf2634832` | `14507ac872dc34a6c20b6f448678466f119de94a4ed1de6d91e269640936c81c` | complete, 0 issues |
| Sink helper | `ecmascript/builtins/builtins_arraybuffer.cpp` | `2aa22c58803df690a5a2b326451e02297dc5e2f6` | `4d388d997313cf7c900f1f0d54fbe826266845665424e32cc9dd4cdbaa62dcc9` | complete, 0 issues |
| Declaration evidence | `ecmascript/builtins/builtins_typedarray.h` | `b291181c949c7038b7030a216f5bdc0e7474a1c2` | `651d426c00c1d8bc6503c1d717decf42b28c61c57336e9418ad422604a6a1be7` | partial, 33 issues |

The scout report `typedarray_copy_mutation_scout_20261020.md` had the target `.cpp` and declaration `.h` blob/SHA rows transposed. This implementation corrected both identities against `git show`/`git hash-object`; the header is pinned but its partial parse is retained as a limitation. M1 indexing over these three exact source files reported 2 complete, 1 partial. The target `BuiltinsTypedArray::Set` slice (lines 1134–1379) and buffer-writer slices (`SetValueInBuffer` lines 380–407 and 722–766; `SetValueInBufferForByte` lines 584–597; `SetTypeData` lines 435–442) each parse completely. Candidate output is therefore retained as `partial`; the rule never promotes the declaration header to complete.

The rule requires the exact repository, commit, target blob+SHA, helper blob+SHA, M1 Git blob facts, full source units, and the expected declaration identity/status. Missing or changed target/helper evidence, wrong repository/profile, unsupported parser state, or a changed binding profile produces no candidate and remains `not_analyzed`. The rule is default-off with the existing explicitly selected Ark Runtime detector. It does not modify Ark Runtime source.

## Source-derived trigger and controls

For a `Uint8Array` target over a 6145-byte buffer with `byteOffset=4096`, `length=2049`, choose a non-stable ordinary array-like object whose `length` is 2049 and whose indices provide numeric values. An offset Number of `2^64 - 2048` is exactly representable in binary64 and lies in the `uint64_t` conversion range.

- `srcLen + targetOffset` wraps to `1`, so the source range check accepts it against `targetLength=2049`.
- `targetOffset * 1 + targetByteOffset` wraps modulo `2^64` to 2048; narrowing to `uint32_t` retains 2048.
- The source computes `limit=4097`. The loop writes backing-store indices `[2048, 4097)`: 2048 bytes before the target view's start at 4096 and one byte at the first byte inside the view. Every index is within the 6145-byte backing allocation.
- The stable-array optimization returns through `FastCopyFromArrayToTypedArray` only when that array predicate succeeds. The candidate route is the ordinary array-like path. The loop rechecks detachment, then dispatches `SetValueInBuffer`; the `Uint8` branch reaches `SetTypeData`, whose byte write uses `*(block + index + i)`. No target-view length check is visible on that path.

| Control | Expected/observed result |
|---|---|
| Exact pinned source with complete target and helper | One candidate at line 1227; M2 run blocked with `partial=1`, `not_analyzed=2` because the exact declaration header is partial. |
| Overflow-safe subtraction guard in the focused method slice | `_has_wrap_shape` returns false; included as a fixed-shape unit control. |
| Small in-range offset/length | Source-derived arithmetic accepts the valid range without wrap. |
| Non-overflowing one-past range | Source-derived range check rejects it. |
| The wrap trigger above | Arithmetic control confirms accepted sum 1 and write-index interval `[2048,4097)`. |
| Stable-array fast path without ordinary array-like operations | No candidate shape. |
| Unrelated sink or altered loop comparison | No candidate shape. |
| Exact target with sink helper omitted from M1 scope | Zero findings, blocked; explicit `arraylike_set_bounds_missing_sink_helper`. |
| Exact local Git bytes declared under the wrong repository identity | Zero findings, blocked; no exact upstream rule binding. |
| Missing/altered binding profile or absent target evidence | Focused tests confirm `not_analyzed`, no observation. |

These are parser/static and source-arithmetic controls. The corrected-source shape was not built into Ark Runtime and was not run as a separate source commit through M2; it is not a dynamic fixed-version validation.

## Verification

- `python -m pytest tests/detectors/ark_runtime/test_arraylike_set_bounds.py tests/detectors/ark_runtime/test_catalog.py -q`: **12 passed**.
- `python -m pytest tests/detectors/ark_runtime -q`: **209 passed, 3 skipped**.
- `python -m compileall -q src/ohscanner/detectors/ark_runtime`: passed.
- `git diff --check`: passed before commit.
- Exact-source M1: 3 files, 2 complete / 1 partial.
- Exact-source M2 (three files, explicitly selected detector): 1 candidate at `builtins_typedarray.cpp:1227`; status `blocked`, coverage `partial=1`, `not_analyzed=2`; `validated_vulnerability=0`.
- M2 with the sink helper omitted: 0 findings, blocked, missing-helper reason retained.
- M2 with mismatched declared repository: 0 findings, blocked, exact-source mismatch retained.

No compiled Ark Runtime execution, isolated PoC, ASan run, architecture/build-profile verification, shipped-product binding, or impact evaluation was performed; those remain `not_run`/`unknown`.

## Independent tester matrix and prompt

Send the developer commit to the independent tester before treating this slice as closed. The tester should independently replay exact-source positive, missing-helper, and wrong-repository M2 cases; exercise the fixed-shape and numeric controls; confirm the header remains partial and candidate output remains partial/blocked; and return any mismatch to the developer for repair before closure.

```text
ROLE=independent Ark Runtime static-detector tester.
INPUT=developer commit SHA, this report, exact source commit a65a2853ccae13da167d9aa4720ab8b11ec16656, corrected target/helper/header pins and the stated M2 matrix.
GOAL=challenge the range-wrap trigger, source route, output wording, and fail-closed provenance on the exact developer commit.
STEPS=verify all source Git blobs/SHA values independently; verify complete Set and byte-writer slices plus the partial declaration state; independently recompute the 64-bit range-sum and 32-bit byte indices; replay exact target+helper M2, missing-helper M2, and wrong-repository M2; test the overflow-safe subtraction, ordinary in-range/one-past, stable-array-only, unrelated-sink, wrong-commit/blob, and mutated-helper controls; return concrete mismatches to developer before closure.
OUTPUT=separate same-commit report with commands, findings/counts, parser/coverage states, and explicit unknown/not_run fields.
STOP=one independent determination; if a mismatch exists, report it to developer before closure and test the repair commit.
NEVER=edit production detector/model, infer safety from zero findings, claim allocation-boundary OOB/runtime exploitability/product impact/formal accuracy, or call an unexecuted control a passing runtime test.
```
