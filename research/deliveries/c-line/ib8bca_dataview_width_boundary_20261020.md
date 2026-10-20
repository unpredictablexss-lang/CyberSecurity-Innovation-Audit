# IB8BCA DataView width-boundary source review — 2026-10-20

## Outcome

No production or test patch was made. The current branch has no `ark.runtime.dataview-index-width-bounds` rule or exact source binding, so its registered replay is **not_run**. The source review identifies a parent-side boundary where `index + elementSize` crosses signed 32-bit range before comparison, but whether that IR sequence takes the suspected bypass requires confirming Ark `Int32Add`/comparison execution semantics; no compiled/runtime test was run. The fixed source widens the bounds check and rejects the first-past-end boundary at source level. No runtime, product, exploitability, or formal accuracy claim is made.

## Source identity

Objects were read from local Git store `D:\openHarmonyScanner\tmp\arkruntime-gitee-audit-20261023.git`.

| Revision | Commit | Tree | Target blob | SHA-256 |
|---|---|---|---|---|
| Parent | `d62f6de64daa7e11a7936a6153748a7c5fae9e41` | `a26f18bc7b1cd97fb926ae61b3655ddbf2caf8d1` | `aedb6d26681535371d1e9ed90b697b923b8100e6` | `bd55a638db7292305dd7b564c5767657e105a48f064c66809934f5e3e6a5f548` |
| Fixed | `48fcec3686e45175f95b4600b579026a65149966` | `6ff7f405071d29fc3ecf9bac1abd9d59a485909f` | `dce9388e8b7e33c87aec33ac4d067fe40370561b` | `89fd548588f59a5f0756868957ff011609264b7d10437a8636c3f3262da1d386` |

Supporting source identity at the parent: `builtins_dataview.cpp` blob `e6bac984354292405ae62f7728170d7be5e3760e`, SHA-256 `bc01e0f8b8a2a5ab30d1478587b45a14aa8130d3d53dfb32b9513ff4d73bc38c`; `js_dataview.h` blob `c93f078ecd4ef400ba035b996e776c3759f6e56e`, SHA-256 `e743389708ba597f23a8a4d1337aea07590376307d919b0656c8322b9b5bd989`; `builtins_arraybuffer.cpp` blob `2e45d892c87d8c0e443862c4cce2241c677e8646`, SHA-256 `6b7016348fafb93dc9875a497c752ccadffba4221827dbb706941273b48c41dc`.

## Guard and store trace

In both target versions, `SetTypedValue` checks `TaggedIsHeapObject(thisValue)`, `IsDataView(thisValue)`, `TaggedIsInt(indexTagged)`, and then branches to `slowPath` when the extracted `index` is negative (target lines 32–50). It validates the value as numeric and checks detachment before loading view offset and length (lines 52–74).

In the parent (lines 72–93), `size` and `elementSize` feed `Int32GreaterThan(Int32Add(index, elementSize), size)`. If this check passes, it forms `bufferIndex = Int32Add(index, offset)` and calls the store helper. `INT32`/`FLOAT32` use the 4-byte `SetValueInBufferForInt32`; `FLOAT64` uses the 8-byte `SetValueInBufferForInt64`. Those helpers write four/eight successive bytes (parent lines 126–137 and 170–177).

The fixed source zero-extends `size`, `elementSize`, and nonnegative `index` to 64 bits, compares `Int64Add(indexInt64, elementSize)` with unsigned greater-than (lines 72–75), then forms `bufferIndex = TruncInt64ToInt32(Int64Add(indexInt64, offset))` (lines 78–79). The first-past-end value below is greater than `size` in that widened comparison and takes `slowPath` before the store.

`BuiltinsDataView` construction checks `offset <= bufferByteLength` and `offset + viewByteLength <= bufferByteLength` before storing the view fields as `uint32_t` (`builtins_dataview.cpp` lines 54–91). `AllocateArrayBuffer` rejects requested byte lengths greater than `INT_MAX` (parent `builtins_arraybuffer.cpp` line 238); equality is allowed by this source check, but backing allocation success at that size is unverified. Under these source invariants, if the fixed widened guard passes, then `index + elementSize <= viewByteLength` and `byteOffset + viewByteLength <= bufferByteLength <= INT_MAX`; therefore `index + byteOffset` plus the store width fits in the underlying buffer and its conversion back to `int32_t` is representable. This is a source-invariant argument, not a runtime proof; mutation/resizable-buffer behavior is not covered.

## Boundary matrix sent to independent tester

The exact matrix was sent before finalizing. Let `w=4` for `INT32` and `FLOAT32`, `w=8` for `FLOAT64`, `size=INT32_MAX`, and `byteOffset=0` unless stated otherwise.

| Case | Input | Parent source expectation | Fixed source expectation |
|---|---|---|---|
| Small positive control | `index=0`, `size=w` | `0+w > w` is false; store path | Widened comparison is false; store path |
| Last valid index | `index=size-w` | Mathematical sum equals size; enters store path | Widened sum equals size; enters store path |
| First past end | `index=size-w+1` (`2147483644` for `w=4`; `2147483640` for `w=8`) | Mathematical sum is `2^31`; `Int32Add`/signed compare may wrap such that guard passes. This remains an IR-semantics hypothesis, not an observed outcome. | Widened sum is `2147483648 > INT32_MAX`; takes `slowPath`, no store at source level. |
| Larger nonnegative tagged index | `index=INT32_MAX`, `size=INT32_MAX` | Sum crosses signed range; parent branch outcome unverified. | Sum is greater than size; takes `slowPath`. |
| Negative control | `index=-1` tagged integer | Negative guard takes `slowPath` before arithmetic. | Same. |
| Absolute end control | `size=w`, `byteOffset=INT32_MAX-w`, `index=0` | `index+offset` is representable; store occupies half-open `[INT32_MAX-w, INT32_MAX)`. | Same; the subsequent 64-to-32 conversion is representable. |

The independent tester confirmed the identities, sequence, and boundary arithmetic. It independently classifies parent overflow/branch behavior as unknown pending IR/runtime semantics and confirms fixed widened rejection. Its baseline report is commit `22a6a2c8768bd18b3f169fa3e1ed47ef027f3853`, `research/deliveries/c-line/ib8bca_dataview_independent_baseline_20261020.md` in the tester worktree. No discrepancies remain between the developer matrix and independent source baseline.

## Rule availability and validation

I searched the active branch's `src/ohscanner`, tests, and C-line reports for `ark.runtime.dataview-index-width-bounds`, `IB8BCA`, and DataView index-width bindings. No matching rule/binding is present. The rule version `1.0.0` appears only in the historical task description, not as an available detector on this branch. Accordingly, the registered rule/CLI replay is **not_run**, not zero findings and not a safe verdict. No detector invocation was substituted for the missing rule.

Regression command: `python -m pytest tests/detectors/ark_runtime tests/detectors/test_cpp_memory_safety_detectors.py -q` — **179 passed, 3 skipped**. This checks existing suites only; it is not an IB8BCA rule replay.

Remaining unknowns: exact Ark IR overflow/comparison semantics for this generated path; runtime behavior of out-of-view stores; allocation success for an `INT_MAX` buffer; concrete source/build/profile selection; and any product impact. The report is scoped to the two exact source revisions only.
