import assert from "node:assert/strict";
import test from "node:test";
import { hashPresentation } from "../src/hash.js";

test("missing hashes render safely without a copy action", () => {
  for (const value of [undefined, null, ""]) {
    assert.deepEqual(hashPresentation(value), { text: "未知", copyable: false });
  }
});

test("present hashes show a short label and copy the full value", () => {
  const value = "0123456789abcdef";
  assert.deepEqual(hashPresentation(value), {
    text: "0123456789ab",
    copyable: { text: value },
  });
});
