import test from "node:test";
import assert from "node:assert/strict";
import { chineseNarrative } from "../src/features/cases/chineseNarrativeText.js";

test("keeps Chinese report prose visible", () => {
  assert.deepEqual(chineseNarrative("该报告说明当前影响未知。"),
    { text: "该报告说明当前影响未知。", original: "", isChinese: true });
});

test("folds historical English prose without losing its original text", () => {
  const result = chineseNarrative("The report needs a human review.");
  assert.equal(result.isChinese, false);
  assert.match(result.text, /该说明主要为英文/);
  assert.equal(result.original, "The report needs a human review.");
});

test("folds English prose embedded after a short Chinese prefix but keeps technical identifiers", () => {
  const prose = chineseNarrative("该调用 may return null when the guard is missing.");
  assert.equal(prose.isChinese, false);
  assert.match(prose.text, /已折叠原文/);
  const technical = chineseNarrative("调用 ReadCastRemoteDevice 检查 MAX_DEVICE_NUM 边界");
  assert.equal(technical.isChinese, true);
});

test("folds mostly English text even when a short Chinese prefix is present", () => {
  const result = chineseNarrative("该调用会读取 index and may write past the buffer unless checked.");
  assert.equal(result.isChinese, false);
  assert.match(result.text, /该说明主要为英文/);
  assert.match(result.original, /write past the buffer/);
});
