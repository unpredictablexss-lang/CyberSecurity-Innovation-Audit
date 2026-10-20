# DataView GetViewValue / SetViewValue second-layer review — 2026-10-20

**Disposition:** The replayed `uint32` arithmetic pattern does not, by itself, establish a source-level out-of-bounds access in these APIs. The parent has an index-width/conversion limitation, but available constructor and allocator invariants counter the proposed wraparound-to-OOB path. No compiled/runtime/product conclusion is supported.

## Provenance

Pinned store: `D:\openHarmonyScanner\tmp\arkruntime-gitee-audit-20261023.git`; source `ecmascript/builtins/builtins_dataview.cpp`.

| Role | Commit | Tree | Blob | SHA-256 |
|---|---|---|---|---|
| Parent | `d62f6de64daa7e11a7936a6153748a7c5fae9e41` | `a26f18bc7b1cd97fb926ae61b3655ddbf2caf8d1` | `e6bac984354292405ae62f7728170d7be5e3760e` | `bc01e0f8b8a2a5ab30d1478587b45a14aa8130d3d53dfb32b9513ff4d73bc38c` |
| Fixed | `48fcec3686e45175f95b4600b579026a65149966` | `6ff7f405071d29fc3ecf9bac1abd9d59a485909f` | `a2376e822e995333b2400520ca5b882de9578b5e` | `39b1ed79451980ad85e1176805deaf6c6315bca09d7676ea5c63f5ff1c4bd65b` |

All identities match the task pins.

## Source trace and invariants

In the parent `GetViewValue` (lines 338–396), integer inputs use signed `int32_t`; other inputs use `ToNumber` followed by saturating/truncating `DoubleInRangeInt32` (lines 352–369). It rejects negative `indexInt`, casts to `uint32_t`, then checks `index + elementSize > size` (lines 370–395). Parent `SetViewValue` (lines 400–461) uses `int64_t` for its temporary index, but also clamps non-integer inputs through `DoubleInRangeInt32`; it then casts to `uint32_t` for the bounds check and buffer-index sum (lines 416–461).

The fixed source converts indices through `ToIndex` into `uint64_t` in both APIs, checks `index + elementSize > size` in that wider type, then narrows the final buffer index (Get lines 352–395; Set lines 413–461). This avoids relying on bounded signed conversion for large indices.

The constructor (parent lines 24–91) reads the backing buffer’s `uint32_t` byte length, checks offset against it, and checks `offset + viewByteLen <= bufByteLen` before storing view length and offset as `uint32_t`. `ToIndex` values are at most `SAFE_NUMBER`, so the constructor’s intermediate `uint64_t` addition cannot wrap. The same checks exist in the fixed source. The `ArrayBuffer` allocator in this pinned tree additionally rejects byte lengths above `INT_MAX` (`ecmascript/builtins/builtins_arraybuffer.cpp`, `AllocateArrayBuffer`), which is a stronger practical bound for ordinary buffers created through that API.

The sinks are direct: `GetValueFromBuffer` receives a `uint32_t byteIndex` and indexes the block (for example, one-byte reads use `block[byteIndex]`; wider types use typed helper reads). `SetValueInBuffer` similarly passes the index to direct typed/byte stores. They do not add an independent range check. However, for a valid DataView, constructor invariants give `offset + size <= backingBufferLength`. If the preceding `index + elementSize <= size` test succeeds, `index + offset` is within the backing buffer. In the parent, the converted index is at most `INT32_MAX`, and adding supported element sizes (at most 8) cannot wrap a `uint32_t`; if that sum exceeds view size, the operation throws before reaching the sink. Therefore the specific uint32 wraparound route to an out-of-bounds sink is not supported by these source bounds.

## Candidate assessment and unknowns

Parent conversion can clamp a non-integer numeric index above `INT32_MAX` to `INT32_MAX`, while fixed `ToIndex` preserves the larger valid index. For a view whose length is bounded by the ordinary `INT_MAX` allocator limit, that clamped index plus a positive element size fails the view bounds check; it does not create an accepted sink access. For fractional inputs, `DoubleInRangeInt32` truncates, which is consistent with `ToIndex`’s integer conversion for finite values. The parent Get path’s use of `ToNumber` rather than `ToIndex` still merits semantic review for special values and exact spec conformance, but this source review found no demonstrated memory-safety effect.

The candidate is therefore **unsupported as an out-of-bounds arithmetic finding on these API source paths**, given the pinned constructor and backing-length invariants. A narrower API-conversion compatibility concern remains possible, especially for nonstandard or externally backed buffers exceeding the ordinary allocator limit; no such supported path was established here.

Unverified: exact lowering/semantics of all native helpers, externally supplied/shared-buffer maximum sizes, any resizable/growable-buffer behavior in this revision, runtime reachability of boundary values, compiled build behavior, and product impact. No build, runtime test, exploit test, or product validation was performed. This is not a product-safety conclusion.
