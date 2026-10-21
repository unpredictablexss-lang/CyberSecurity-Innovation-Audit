import test from "node:test";
import assert from "node:assert/strict";
import { evidenceLocation, evidenceSourceLocation } from "../src/features/audits/agentEvidenceLocation.js";

test("initial candidate citations point to the bound source excerpt range", () => {
  const result = { binding: { file: "src/candidate.cpp" }, initial_evidence: {
    evidence_id: "initial-1", source_excerpt_start_line: 10, source_excerpt_end_line: 20,
  } };
  assert.equal(evidenceLocation(result, "initial-1"), "src/candidate.cpp:10-20 · 初始候选");
});

test("symbol-search citations resolve to exact matching lines and file", () => {
  const result = { tool_calls: [{ evidence_id: "tool-1", result: { matches: [
    { file: "src/a.cpp", line: 40, context_start_line: 38, text: "38: before\n42: const int UID = 3020;\n43: after" },
    { file: "src/b.cpp", line: 8, context_start_line: 6, text: "6: unrelated\n8: const int UID = 3020;" },
  ] } }] };
  assert.equal(evidenceLocation(result, "tool-1", "const int UID = 3020;"),
    "src/a.cpp:42-42；src/b.cpp:8-8 · 扫描代码版本");
});

test("missing exact quote falls back to the bounded source context", () => {
  const result = { tool_calls: [{ evidence_id: "tool-2", result: { matches: [
    { file: "src/a.cpp", line: 12, context_start_line: 10, text: "10: a\n11: b\n12: c\n13: d\n14: e" },
  ] } }] };
  assert.equal(evidenceLocation(result, "tool-2", "not present"), "src/a.cpp:10-14 · 扫描代码版本");
});

test("unavailable evidence is explicit and does not invent a source location", () => {
  assert.equal(evidenceLocation({ tool_calls: [] }, "missing"), "证据记录不可用");
});

test("source locations identify the exact cited line for deep links", () => {
  const result = { binding: { job_id: "job-1", file: "src/candidate.cpp" }, initial_evidence: {
    evidence_id: "initial-1", source_excerpt_start_line: 10, context: { source_excerpt: "before\nreturn false;" },
  }, tool_calls: [{ evidence_id: "tool-1", result: { matches: [
    { file: "src/helper.cpp", line: 40, context_start_line: 38, text: "38: before\n42: verify_access();" },
  ] } }] };
  assert.deepEqual(evidenceSourceLocation(result, "initial-1", "return false;"), { file: "src/candidate.cpp", line: 11 });
  assert.deepEqual(evidenceSourceLocation(result, "tool-1", "verify_access();"), { file: "src/helper.cpp", line: 42 });
  assert.equal(evidenceSourceLocation(result, "missing"), null);
});

test("multiline initial-source citations open at the exact first line and show the full range", () => {
  const result = { binding: { job_id: "job-1", file: "src/candidate.cpp" }, initial_evidence: {
    evidence_id: "initial-multiline", source_excerpt_start_line: 50, source_excerpt_end_line: 54,
    source_excerpt: "before();\nif (!authorized) {\n  return false;\n}\nafter();",
  } };
  const quote = "if (!authorized) {\n  return false;\n}";
  assert.deepEqual(evidenceSourceLocation(result, "initial-multiline", quote),
    { file: "src/candidate.cpp", line: 51 });
  assert.equal(evidenceLocation(result, "initial-multiline", quote),
    "src/candidate.cpp:51-53 · 初始候选");
});

test("multiline fixed-source citations strip displayed line numbers and resolve exact bounds", () => {
  const result = { binding: { job_id: "job-1" }, tool_calls: [{
    evidence_id: "range-1", result: { file: "src/helper.cpp", start_line: 100, end_line: 103,
      text: "100: if (!authorized) {\n101:   return false;\n102: }\n103: after();" },
  }] };
  const quote = "100: if (!authorized) {\n101:   return false;\n102: }";
  assert.deepEqual(evidenceSourceLocation(result, "range-1", quote),
    { file: "src/helper.cpp", line: 100 });
  assert.equal(evidenceLocation(result, "range-1", quote),
    "src/helper.cpp:100-102 · 扫描代码版本");
});

test("explicit line-range citations stay bound to one file when symbol search found several files", () => {
  const result = { tool_calls: [{ evidence_id: "lookup-1", result: { matches: [
    { file: "src/a.cpp", line: 40, context_start_line: 38, text: "38: before\n40: check();" },
    { file: "src/b.cpp", line: 8, context_start_line: 6, text: "6: before\n8: check();" },
  ] } }] };
  const citation = { file: "src/b.cpp", line_start: 8, line_end: 8 };
  assert.equal(evidenceLocation(result, "lookup-1", "check();", citation), "src/b.cpp:8-8");
  assert.deepEqual(evidenceSourceLocation(result, "lookup-1", "check();", citation),
    { file: "src/b.cpp", line: 8 });
});
