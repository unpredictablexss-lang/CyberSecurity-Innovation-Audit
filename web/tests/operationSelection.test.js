import test from "node:test";
import assert from "node:assert/strict";
import { refreshSelectedOperation } from "../src/pages/operationSelection.js";

test("an old detail response cannot replace a newer selected operation", async () => {
  let selectedId = "old";
  let displayed = { id: "old", detail: "initial" };
  let resolveOld;
  const oldRequest = refreshSelectedOperation(
    "old",
    () => new Promise((resolve) => { resolveOld = resolve; }),
    () => selectedId,
    (item) => { displayed = item; },
  );

  selectedId = "new";
  displayed = { id: "new", detail: "fresh" };
  resolveOld({ id: "old", detail: "stale" });
  await oldRequest;

  assert.deepEqual(displayed, { id: "new", detail: "fresh" });
});
