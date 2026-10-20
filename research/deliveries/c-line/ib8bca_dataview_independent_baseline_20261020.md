# IB8BCA DataView `SetTypedValue` independent source baseline

## Scope and source identity

This is an independent static source trace for the recorded parent/fixed pair. It is not runtime execution, a product claim, or a registered detector replay.

I read `ecmascript/compiler/builtins/builtins_dataview_stub_builder.cpp` from the task's local Git object store `D:\openHarmonyScanner\tmp\arkruntime-gitee-audit-20261023.git`. The identity checks used `git --git-dir <store> rev-parse <commit>^{tree}`, `git --git-dir <store> rev-parse <commit>:<path>`, and `git --git-dir <store> show <commit>:<path>` followed by SHA-256 over the exact bytes.

| Revision | Commit | Tree | Blob | SHA-256 |
|---|---|---|---|---|
| Parent | `d62f6de64daa7e11a7936a6153748a7c5fae9e41` | `a26f18bc7b1cd97fb926ae61b3655ddbf2caf8d1` | `aedb6d26681535371d1e9ed90b697b923b8100e6` | `bd55a638db7292305dd7b564c5767657e105a48f064c66809934f5e3e6a5f548` |
| Fixed | `48fcec3686e45175f95b4600b579026a65149966` | `6ff7f405071d29fc3ecf9bac1abd9d59a485909f` | `dce9388e8b7e33c87aec33ac4d067fe40370561b` | `89fd548588f59a5f0756868957ff011609264b7d10437a8636c3f3262da1d386` |

The object IDs, trees and hashes match the execution-tree pin and the developer's independently reported identities.

## Source trace

In the parent, `SetTypedValue` is at lines 25 onward. It obtains the index as an int32 at line 48, branches negative indexes to `slowPath` at line 49, gets byte offset, byte length and element size at lines 72–74, and applies `Int32GreaterThan(Int32Add(index, elementSize), size)` at line 75. If the guard proceeds, it computes `Int32Add(index, offset)` at line 78 and calls a type-specific store at lines 83–92.

The explicit template instantiations are INT32 (line 102), FLOAT32 (104), and FLOAT64 (106). INT32 and FLOAT32 use `SetValueInBufferForInt32` (four byte stores); FLOAT64 uses `SetValueInBufferForInt64` (eight byte stores). These widths are the basis for the boundary arithmetic below.

In the fixed version, lines 72–75 zero-extend byte length, element size, and index to int64 before `Int64Add` and `Int64UnsignedGreaterThan`. Lines 78–79 similarly widen the byte offset addition, then truncate the resulting buffer index to int32 before the type-specific store at lines 84–92. This establishes source operation order; it does not establish runtime reachability or the semantics of an executed IR graph.

## Independent arithmetic cases

Let `S` be the view byte length and `w` the type width. The source guard is intended to allow an access when `n + w <= S`, where `n` is the index. The following calculations are arithmetic controls over the source operands, not observed runtime outcomes.

| Case | `S`, `w`, `n` | Mathematical end `n+w` | Parent source observation | Fixed source observation |
|---|---|---:|---|---|
| Negative | any; `n=-1` | not evaluated past negative guard | Negative branch targets `slowPath` before the size guard/store | Same negative branch precedes widened size guard/store |
| Ordinary exact-fit | `S=w`, `n=0` | `w == S` | Equality is not greater-than; source guard's non-slow edge reaches store | Widened unsigned comparison is false; reaches store |
| Exact end, INT32/FLOAT32 | `S=INT32_MAX`, `w=4`, `n=2147483643` | `2147483647 == S` | Mathematical equality | Widened comparison is false; reaches store |
| First byte past end, INT32/FLOAT32 | `S=INT32_MAX`, `w=4`, `n=2147483644` | `2147483648 == S+1` | `Int32Add` expression exceeds signed int32 mathematical range. Whether IR evaluation wraps and therefore changes the signed compare outcome is unknown here. | Widened sum is `2147483648`, greater than `S`; source guard selects `slowPath` |
| Index at end, INT32/FLOAT32 | `S=INT32_MAX`, `w=4`, `n=2147483647` | `2147483651` | Same out-of-range `Int32Add` uncertainty | Widened sum exceeds `S`; source guard selects `slowPath` |
| Exact end, FLOAT64 | `S=INT32_MAX`, `w=8`, `n=2147483639` | `2147483647 == S` | Mathematical equality | Widened comparison is false; reaches store |
| First byte past end, FLOAT64 | `S=INT32_MAX`, `w=8`, `n=2147483640` | `2147483648 == S+1` | `Int32Add` expression exceeds signed int32 mathematical range. Actual IR and branch outcome are not asserted. | Widened sum is `2147483648`, greater than `S`; source guard selects `slowPath` |
| Index at end, FLOAT64 | `S=INT32_MAX`, `w=8`, `n=2147483647` | `2147483655` | Same out-of-range `Int32Add` uncertainty | Widened sum exceeds `S`; source guard selects `slowPath` |
| Ordinary in-range | `S=16`, `w=4`, `n=4` | `8 <= S` | Mathematical comparison permits access | Widened comparison permits access |
| One past end | `S=4`, `w=4`, `n=1` | `5 > S` | No int32 overflow; comparison selects `slowPath` | Widened comparison selects `slowPath` |

Offset control in the fixed source: `n=0`, `byteOffset=INT32_MAX-w` gives a widened buffer index of `INT32_MAX-w`. A `w`-byte store has half-open end `INT32_MAX` (last byte `INT32_MAX-1`), so this particular arithmetic stays within int32 after truncation. It is only an arithmetic control; it does not prove a real DataView or backing buffer of that size exists.

## Detector and execution availability

I searched the current test worktree's `src/ohscanner/detectors/ark_runtime` and `tests/detectors/ark_runtime` for `dataview-index-width-bounds`, `DataViewStubBuilder`, and `SetTypedValue`; no registered rule or exact source binding is present there. The rule is named in the historical C10 record, but it is not available for an exact registered replay on this base. Therefore registered Ark Runtime CLI replay is **not_run**, and effective detector coverage for this source pair is **unknown**. No zero-finding result is reported.

No code patch or same-commit detector change was provided for this source-baseline task at the time of the report. No C++ compiler/runtime experiment was run.

## Unknowns and limits

- The parent source uses `Int32Add` and `Int32GreaterThan` by name. For inputs whose mathematical `n+w` exceeds `INT32_MAX`, this report does not claim the IR result wraps, that the signed comparison observes a negative value, or that the store executes. Those require IR/runtime evidence.
- A view length of `INT32_MAX`, the relevant tagged-int endpoint, and reaching these indexes through a real product path have not been established.
- The fixed widened comparison rejects the listed first-past-end cases at the source level. The later int64-to-int32 truncation is visible, but no runtime pointer validity or backing-buffer relationship is inferred.
- Exact-end controls show only that the comparison permits equality; they do not prove a store completes or allocation succeeds.
- There is no product build profile, runtime validation, or security impact assessment in this report.
