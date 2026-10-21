"use strict";

// Component harness, not Ark Runtime. It models the pinned d1a58 source's
// uint64 range sum, uint32 backing index, and raw backing-store byte writes.
const assert = require("node:assert/strict");
const U64 = 1n << 64n;
const U32 = 1n << 32n;
const mask64 = U64 - 1n;
const mask32 = U32 - 1n;
const offsetNumber = 2 ** 64 - 2048;
const offset = BigInt(offsetNumber);
assert.equal(offset, U64 - 2048n, "binary64 Number witness must be exact");

function oldSourceModel(backing, targetLength, targetByteOffset, source, targetOffset) {
  const srcLength = BigInt(source.length);
  const wrappedSum = (srcLength + targetOffset) & mask64;
  if (wrappedSum > BigInt(targetLength)) throw new RangeError("source range rejected");
  let index = Number((targetOffset + BigInt(targetByteOffset)) & mask32);
  const limit = Number((BigInt(index) + srcLength) & mask32);
  let writes = 0;
  while (index < limit) {
    backing[index] = source[writes++] & 0xff;
    index = (index + 1) >>> 0;
  }
  return { wrappedSum: Number(wrappedSum), first: Number((targetOffset + BigInt(targetByteOffset)) & mask32), limit, writes };
}

function fixedGuardModel(backing, targetLength, targetByteOffset, source, targetOffset) {
  const srcLength = BigInt(source.length);
  if (targetOffset > BigInt(targetLength) || srcLength > BigInt(targetLength) - targetOffset) {
    throw new RangeError("source range rejected by overflow-safe guard");
  }
  const start = targetByteOffset + Number(targetOffset);
  backing.set(source, start);
  return { first: start, limit: start + source.length, writes: source.length };
}

// Old source arithmetic: range sum wraps and writes through the backing store
// 2048 bytes before the requested target view, while all indices stay in-range
// of the 8192-byte ArrayBuffer.
const oldBacking = new Uint8Array(8192);
const source = new Uint8Array(4096).fill(0xa5);
const oldTrace = oldSourceModel(oldBacking, 4096, 4096, source, offset);
assert.deepEqual(oldTrace, { wrappedSum: 2048, first: 2048, limit: 6144, writes: 4096 });
assert.equal(oldBacking.subarray(2048, 4096).every((v) => v === 0xa5), true,
  "sibling view observes the 2048-byte prefix write");
assert.equal(oldBacking.subarray(6144).some((v) => v !== 0), false,
  "write remains below the backing allocation boundary");

// Fixed guard control: reject before any mutation.
const fixedBacking = new Uint8Array(8192);
assert.throws(() => fixedGuardModel(fixedBacking, 4096, 4096, source, offset), RangeError);
assert.equal(fixedBacking.some((v) => v !== 0), false);

// Arithmetic and exception controls for both models.
const smallBacking = new Uint8Array(16);
assert.deepEqual(oldSourceModel(smallBacking, 4, 0, [1, 2, 3, 4], 0n),
  { wrappedSum: 4, first: 0, limit: 4, writes: 4 });
assert.throws(() => oldSourceModel(new Uint8Array(16), 4, 0, [1, 2, 3, 4], 1n), RangeError);
assert.throws(() => fixedGuardModel(new Uint8Array(16), 4, 0, [1, 2, 3, 4], 1n), RangeError);

// Native ECMAScript engine control (Node/V8): required range exception and no
// indexed writes. This is a language-engine control, not Ark Runtime evidence.
const nativeBacking = new ArrayBuffer(8192);
const nativeTarget = new Uint8Array(nativeBacking, 4096, 4096);
let offsetConversions = 0;
let lengthReads = 0;
let indexedReads = 0;
const arrayLike = new Proxy({}, {
  get(_target, key) {
    if (key === "length") { lengthReads++; return 4096; }
    if (typeof key === "string" && /^\d+$/.test(key)) { indexedReads++; return 0xa5; }
    return undefined;
  },
});
assert.throws(() => nativeTarget.set(arrayLike, {
  valueOf() { offsetConversions++; return offsetNumber; },
}), RangeError);
assert.equal(offsetConversions, 1);
assert.equal(lengthReads, 1);
assert.equal(indexedReads, 0);
assert.equal(new Uint8Array(nativeBacking).some((v) => v !== 0), false);

console.log(JSON.stringify({
  harness: "isolated component arithmetic + Node/V8 language control",
  ark_runtime_execution: "not_run",
  number_offset: String(offset),
  old_source_model: oldTrace,
  fixed_guard: "RangeError before writes",
  native_engine_control: { outcome: "RangeError", offsetConversions, lengthReads, indexedReads },
  backing_store_oob: false,
}, null, 2));
