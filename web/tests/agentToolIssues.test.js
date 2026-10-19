import test from "node:test";
import assert from "node:assert/strict";
import { agentToolIssues } from "../src/features/audits/agentToolIssues.js";

test("tool range rejection is visible with the real limit and safe retry guidance", () => {
  const issues = agentToolIssues([{ tool: "read_fixed_source_range", status: "rejected",
    result: { error_code: "source_range_too_large", message: "provider-controlled text" } }]);
  assert.equal(issues.length, 1);
  assert.equal(issues[0].tool, "read_fixed_source_range");
  assert.match(issues[0].message, /最多读取 40 行/);
  assert.doesNotMatch(issues[0].message, /provider-controlled/);
});

test("legacy generic rejection can be explained from its recorded oversized line count", () => {
  const issues = agentToolIssues([{ tool: "read_fixed_source_range", status: "rejected",
    arguments: { file: "src/fixed.cpp", start_line: 180, line_count: 70 },
    result: { error_code: "query_rejected" } }]);
  assert.equal(issues[0].errorCode, "source_range_too_large");
  assert.match(issues[0].message, /最多读取 40 行/);
});

test("unavailable tool evidence is surfaced while completed calls are omitted", () => {
  const issues = agentToolIssues([
    { tool: "lookup_symbol_in_fixed_commit", status: "completed", result: {} },
    { tool: "read_candidate_source", status: "unavailable", result: { error_code: "fixed_evidence_unavailable" } },
  ]);
  assert.equal(issues.length, 1);
  assert.equal(issues[0].status, "unavailable");
  assert.match(issues[0].message, /保持未决/);
});

test("missing or malformed trace remains safe", () => {
  assert.deepEqual(agentToolIssues(null), []);
  assert.equal(agentToolIssues([{ status: "rejected", result: {} }])[0].message,
    "工具未能提供证据；相关义务应保持未决。");
});
