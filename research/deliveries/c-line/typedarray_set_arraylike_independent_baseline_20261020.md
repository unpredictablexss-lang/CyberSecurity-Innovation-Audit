# TypedArray `set(arrayLike, offset)` candidate: independent pre-implementation baseline

Date: 2026-10-20. Tester slice `C-TEST-TYPEDARRAY-SET-ARRAYLIKE-WRAP-20261020`. No detector, model, Ark Runtime source, or task-tree files were modified.

## Verified repository and corrected file identities

Source checkout: `D:\OpenHarmony807\repos\arkcompiler_ets_runtime`, clean at commit `a65a2853ccae13da167d9aa4720ab8b11ec16656`, tree `8781f036a3e7e04d8e0b34970d5f623b42875016`, repository identity `openharmony/arkcompiler_ets_runtime`.

The scout report had the `builtins_typedarray.cpp` and `.h` Git blob OIDs interchanged. Independent `git ls-tree` and OHScanner M1 indexing confirmed the correction below. SHA-256 and parse status were taken from the exact M1 `light-ast` report.

| Path | Verified blob OID | SHA-256 | `light-ast` status |
|---|---|---|---|
| `ecmascript/builtins/builtins_typedarray.cpp` | `0fc27c213e1ea80d93e1e3807eec11baf2634832` | `14507ac872dc34a6c20b6f448678466f119de94a4ed1de6d91e269640936c81c` | complete, 0 issues |
| `ecmascript/builtins/builtins_typedarray.h` | `b291181c949c7038b7030a216f5bdc0e7474a1c2` | `651d426c00c1d8bc6503c1d717decf42b28c61c57336e9418ad422604a6a1be7` | partial, 33 issues |
| `ecmascript/builtins/builtins_array.cpp` | `641b7785acd6cf73abcd404dcdcf0727c92c1fda` | `6c7a2081e8d59311099b4ebaed6d4f1f84265a8602ba8de647e65fa7c6092cfa` | complete, 0 issues |
| `ecmascript/base/typed_array_helper.cpp` | `bcb422fe67f4e670adcca31fffd4da7e2b3b0b21` | `3c42388b716e82601cee4e43aedddc8ac709fe1363b0753c7efa24745380110d` | complete, 0 issues |
| `ecmascript/base/typed_array_helper.h` | `92b73cdcf4b4e05453cc21e24f7e9364dd6949ce` | `ced087d43a805171778d0ff49f46c01568588fdb137b3c5583a472d9de83491a` | partial, 4 issues |
| `ecmascript/js_typed_array.cpp` | `098c2a22cae3152af3a59063dda25e145f03bbd7` | `e67c0ce082885efb6fa5894f7a1998a41eb4cddfa2e381c8335497e10e2b9bbe` | complete, 0 issues |
| `ecmascript/js_typed_array.h` | `d59bc3138542afa22bfe2a2f42f5fa756a6dae1a` | `a22084f1746bbfe86656a92d4847bebfab3057e667b25bcb0853cc648c29e669` | partial, 8 issues |
| `ecmascript/builtins/builtins_arraybuffer.cpp` | `2aa22c58803df690a5b2a326451e02297dc5e2f6` | `4d388d997313cf7c900f1f0d54fbe826266845665424e32cc9dd4cdbaa62dcc9` | complete, 0 issues |
| `ecmascript/builtins/builtins_arraybuffer.h` | `c938b4263bdae62c1418dc8ca159b2ba8bc0a493` | `c2a4fb1a18e785d1f105eee52ac71a38386b93a6ac80b685c438edf48e3fe9e6` | complete, 0 issues |

M1 summary over these nine files: 9 C++ sources, 6 complete and 3 partial. The three incomplete files are headers; their parse state remains partial and must not be upgraded by nearby complete `.cpp` files. The precise candidate body `builtins_typedarray.cpp` and write helpers `builtins_arraybuffer.cpp` are complete under this parser profile; that does not add compiler flags, macro expansion, runtime dispatch, or product evidence.

## Independent arithmetic and route review

I reread the pinned `BuiltinsTypedArray::Set` array-like branch at `builtins_typedarray.cpp` around lines 1157–1241 and the byte write path at `builtins_arraybuffer.cpp` around lines 401–406 and 722–749.

For the scout's Uint8Array values, the arithmetic reproduces exactly:

| Quantity | Value / operation | Result |
|---|---|---|
| Target backing allocation | 6145 bytes | Valid target view: byte offset 4096, element length 2049 |
| Source-like length | 2049 | Ordinary non-stable array-like object required to enter the generic array-like branch |
| Offset | `2^64 - 2048` = `18446744073709549568` | Exactly representable binary64 integer; within `uint64_t` range |
| Range-check sum | `(offset + 2049) mod 2^64` | 1, so `1 > targetLength(2049)` is false |
| Widened byte-offset assertion | `(offset * 1 + 4096) mod 2^64` | 2048, satisfies `<= UINT32_MAX` |
| Stored `uint32_t targetByteIndex` | `(uint32_t(offset) + 4096) mod 2^32` | 2048 |
| `uint32_t limit` | `targetByteIndex + 2049` | 4097 |
| Loop write range | `[2048,4097)` | 2049 writes; 2048 bytes precede the target view at 4096, and byte 4096 is the first target-view byte |
| Backing-store boundary | end index 4097 vs length 6145 | All candidate writes remain inside the backing allocation |

I independently evaluated binary64 and unsigned-wrap operations with Python; the result was exactness `true`, in-range-for-uint64 `true`, wrapped sums 1 and 2048, target byte index 2048, limit 4097, 2049 iterations, and 2048 writes before the target view. I found no arithmetic counterexample to the conditional **cross-view write** source hypothesis. This is not an allocation-boundary OOB claim.

The overload selection matters: a packed/stable JS Array may take `JSStableArray::FastCopyFromArrayToTypedArray` before the general array-like branch. The advertised trigger therefore uses an ordinary non-stable object with a `length` property and indexed values. The exact binary64 argument conversion, source loop behavior, and byte writes were not executed in Ark Runtime. A nonzero target view offset and a second view sharing the buffer are necessary to interpret the earlier bytes as cross-view corruption.

## Current scanner/direct-analysis baseline

Exact M1 and M2 commands used the nine paths listed above, source commit/tree above, and explicit detector `ohscanner.ark.runtime.type_safety`. Reports were saved outside the repository:

- `D:\OpenHarmonyScanner\tmp\typedarray-set-arraylike-index-baseline.json`
- `D:\OpenHarmonyScanner\tmp\typedarray-set-arraylike-index-baseline.md`
- `D:\OpenHarmonyScanner\tmp\typedarray-set-arraylike-run-baseline.json`
- `D:\OpenHarmonyScanner\tmp\typedarray-set-arraylike-run-baseline.md`

M2 baseline: completed with limitations, zero diagnostics, detector coverage blocked. The detector had scope size 0; its only coverage-sidecar entry was the already modeled `ecmascript/base/typed_array_helper.cpp` source dependency, marked not analyzed because the exact repository/commit/path is not a rule target. This is not a clean analysis or safe result for `%TypedArray%.prototype.set`.

I also called the existing direct `analyze_unit` seam with `c_line_static_model()` and `research_partial=True` on all nine exact indexed source units. Six complete `.cpp` files returned `completed/complete`, zero observations, `not_applicable_to_rule`. The three partial headers returned `limited/not_analyzed`, zero observations, `target_not_resolved_in_partial_ast`. This confirms no existing direct rule for the Set array-like flow and preserves incomplete header evidence as unknown.

## Controls to replay on a developer commit

These are expected controls only until executed by the detector or an Ark Runtime build:

| Control | Expected interpretation |
|---|---|
| Exact source positive: ordinary non-stable array-like, source length 2049, Uint8 target view offset 4096 / length 2049, backing 6145, offset `2^64 - 2048` | At most one narrow candidate for the array-like unsigned range-sum plus narrowed byte-index path; do not report an out-of-allocation write. |
| In-range offset 0 with length 2049 | No candidate; ordinary in-range behavior. |
| One-past offset 1 with length 2049 and target length 2049 | Range check rejects; no candidate. |
| Fixed predicate `offset > targetLength || srcLen > targetLength - offset` (after validating offset) | Exact fixed source should not take the wrap path. If its commit/blob is not registered, CLI zero findings must be recorded as unbound/unknown, not safe. |
| Zero-byte-offset target view | The earlier-byte cross-view interpretation does not apply; retain only what exact rule semantics support. |
| Stable packed Array source | Must distinguish or fail closed rather than assuming it reaches the ordinary array-like branch. |
| Wrong repository/commit/blob/SHA | Zero findings with blocked/not-analyzed identity mismatch, never analyzed-safe. |
| Missing or mutated `SetValueInBuffer` / relevant method helper | Dependency missing/mismatch must stay blocked/unknown; no candidate trace may claim complete write semantics. |
| Incomplete parser evidence | Preserve partial/unknown; do not promote a whole translation unit to complete from a local snippet. |

No runtime, build, ASan, product profile, or out-of-bounds/cross-view effect was tested. No exploitability or product impact is asserted.
