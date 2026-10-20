# IB8BCA second-layer source review — 2026-10-20

**Disposition: plausible source-level bounds-check bypass candidate; compiled/runtime effect and impact unknown.** This review is limited to exact source at the two pinned commits. It does not claim a compiled-stub defect or product vulnerability.

## Provenance

Pinned store: `D:\openHarmonyScanner\tmp\arkruntime-gitee-audit-20261023.git`.

| Role | Commit | Tree | File blob | File SHA-256 |
|---|---|---|---|---|
| Parent | `d62f6de64daa7e11a7936a6153748a7c5fae9e41` | `a26f18bc7b1cd97fb926ae61b3655ddbf2caf8d1` | `aedb6d26681535371d1e9ed90b697b923b8100e6` | `bd55a638db7292305dd7b564c5767657e105a48f064c66809934f5e3e6a5f548` |
| Fixed | `48fcec3686e45175f95b4600b579026a65149966` | `6ff7f405071d29fc3ecf9bac1abd9d59a485909f` | `dce9388e8b7e33c87aec33ac4d067fe40370561b` | `89fd548588f59a5f0756868957ff011609264b7d10437a8636c3f3262da1d386` |

All identity values match the planning tree. File reviewed: `ecmascript/compiler/builtins/builtins_dataview_stub_builder.cpp`.

## Source trace

In `SetTypedValue` (parent lines 38–49), the fast path requires a tagged integer index, extracts it as `int32`, and rejects negative values. It checks that the value is numeric and the buffer is not detached (lines 52–70). The parent then obtains view byte length and element size and tests `Int32Add(index, elementSize) > size` (lines 72–75). A false comparison enters the write path; it computes `bufferIndex = Int32Add(index, byteOffset)` (line 78), obtains the data pointer, and stores at that offset (lines 80–93). Four-byte stores use four byte writes in `SetValueInBufferForInt32`; the float64 specialization uses `SetValueInBufferForInt64` (defined below this function).

The source explicitly instantiates `SetTypedValue` for `INT32`, `FLOAT32`, and `FLOAT64` (parent lines 102–106). The `GetElementSize(type)` operation therefore supplies sizes 4, 4, and 8 respectively, subject to the actual DSL/compiler lowering.

For a nonnegative signed 32-bit `index`, the parent addition can wrap at these high-end values:

| Instantiation | Element size | First index whose sum exceeds `INT32_MAX` | Wrapped sum (two’s-complement expectation) |
|---|---:|---:|---:|
| INT32 | 4 | 2,147,483,644 | `INT32_MIN` |
| FLOAT32 | 4 | 2,147,483,644 | `INT32_MIN` |
| FLOAT64 | 8 | 2,147,483,640 | `INT32_MIN` |

With a small view length, a negative wrapped sum is not greater than the positive length under signed comparison. The source thus supports a plausible bypass of the local view-length guard for those high indices. The subsequent parent `index + byteOffset` is also 32-bit arithmetic. If the branch behaves as its source-level operands suggest, the write can use an offset far beyond a short view and possibly beyond its backing buffer.

The fixed source (lines 72–79) zero-extends view length, element size, index, and byte offset to 64 bits; it performs an unsigned 64-bit comparison on `index + elementSize` before entering the write path. It then adds index and offset in 64 bits and truncates the final buffer index to 32 bits only after the bounds branch. That order removes the parent’s obvious signed-add wraparound path, conditional on the source DSL operations lowering as named and on DataView/view invariants constraining the final sum.

## Counterevidence and limits

- The source does not establish how `BRANCH`, `Int32Add`, `Int64Add`, `Int64UnsignedGreaterThan`, zero-extension, truncation, or `Store` lower on any supported backend. No compiled stub or IR was inspected.
- A `TaggedIsInt` argument reaching this fast path depends on the engine’s tagged-integer representation and call-site behavior. Whether ordinary JS can supply each boundary value on this path rather than taking the slow path is unverified.
- The source excerpt does not establish backing-buffer maximum size, DataView construction invariants, pointer arithmetic behavior, allocation feasibility at near-2-GiB sizes, or whether memory-safety instrumentation/other checks intervene.
- No runtime test, generated-code analysis, sanitizer run, product build, or product deployment evidence was collected. Trigger reachability and security impact remain unknown.
- The fixed code’s final 64-to-32-bit truncation appears safe only if the successful bounds check plus valid DataView byteOffset/length invariants ensure `index + byteOffset` fits the intended buffer index domain; those invariants were not independently traced here.

**Conclusion:** retain IB8BCA as a source-level candidate for second-layer follow-up. The parent’s signed 32-bit add-before-compare is a credible check-bypass pattern for all three explicit instantiations, and the fixed source widens the guard arithmetic. Whether this becomes an out-of-bounds write in compiled Ark or affects a product is unknown. Do not promote it to a confirmed vulnerability on this evidence.
