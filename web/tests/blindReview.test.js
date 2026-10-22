import test from "node:test";
import assert from "node:assert/strict";
import { blindReviewOperationIds, blindReviewPairs } from "../src/features/audits/blindReview.js";

function operation(id, mode, overrides = {}) {
  return {
    id, kind: "agent_investigation", status: "completed", result_sha256: `${id}-result-hash`,
    spec: { experiment_id: "study-1", mode, pair_id: "pair-1", candidate_id: "candidate-12345678901234567890",
      source_commit: "a".repeat(40), job_id: "job-1", report_sha256: "b".repeat(64),
      candidate_source_sha256: "c".repeat(64), ...overrides },
  };
}

test("blind review options contain complete AI 初步分析与 AI 深入追查 pairs and expand to both operation IDs", () => {
  const rows = [operation("r1", "single_shot"), operation("r2", "tool_agent")];
  const result = blindReviewPairs(rows, "study-1");
  assert.equal(result.eligibleOperationCount, 2);
  assert.equal(result.pairs.length, 1);
  assert.match(result.pairs[0].label, /两种调查均完成/);
  assert.deepEqual(blindReviewOperationIds([result.pairs[0].key], result.pairs), ["r1", "r2"]);
});

test("incomplete and ambiguous candidate pairs are excluded from selection", () => {
  const rows = [
    operation("only-r1", "single_shot", { pair_id: "incomplete" }),
    operation("r1-a", "single_shot", { pair_id: "ambiguous" }),
    operation("r1-b", "single_shot", { pair_id: "ambiguous" }),
    operation("r2", "tool_agent", { pair_id: "ambiguous" }),
  ];
  const result = blindReviewPairs(rows, "study-1");
  assert.deepEqual(result.pairs, []);
  assert.equal(result.incompletePairCount, 1);
  assert.equal(result.ambiguousPairCount, 1);
});

test("fallback binding pairs legacy rows, while unrelated or unfinished rows are ignored", () => {
  const identity = { pair_id: undefined };
  const rows = [
    operation("legacy-r1", "single_shot", identity),
    operation("legacy-r2", "tool_agent", identity),
    operation("other-study", "single_shot", { experiment_id: "study-2" }),
    { ...operation("queued", "tool_agent", { pair_id: "queued" }), status: "queued" },
    { ...operation("no-result", "tool_agent", { pair_id: "no-result" }), result_sha256: null },
    { ...operation("other-kind", "single_shot"), kind: "investigation" },
  ];
  const result = blindReviewPairs(rows, "study-1");
  assert.equal(result.pairs.length, 1);
  assert.deepEqual(result.pairs[0].operationIds, ["legacy-r1", "legacy-r2"]);
  assert.equal(result.eligibleOperationCount, 2);
});
