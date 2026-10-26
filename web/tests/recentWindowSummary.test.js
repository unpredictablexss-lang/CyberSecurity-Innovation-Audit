import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

function loadSummaryBuilder() {
  const componentPath = resolve(dirname(fileURLToPath(import.meta.url)),
    "../src/features/audits/OperationWorkspace.tsx");
  const source = readFileSync(componentPath, "utf8").replace(/\r\n/g, "\n");
  const start = source.indexOf("export function buildRecentWindowSummary");
  const end = source.indexOf("\n}\n\nfunction RecentWindowSummary", start);
  assert.ok(start >= 0 && end > start, "the task-detail summary helper should stay in OperationWorkspace");
  const declaration = source.slice(start, end + 2);
  const compiled = ts.transpileModule(declaration, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  const module = { exports: {} };
  new Function("exports", "module", compiled)(module.exports, module);
  return module.exports.buildRecentWindowSummary;
}

test("N-day/1-day detail summarizes fixed endpoints and candidate observations without attribution", () => {
  const build = loadSummaryBuilder();
  const result = build({
    status: "completed_with_limitations", lookback_days: 7,
    reference_time: "2026-10-21T12:00:00+08:00", timezone: "Asia/Shanghai",
    scan_ids: ["n-before", "n-after", "one-before", "one-after"], impact: "unknown",
    validated_vulnerability: 0,
    windows: [
      { label: "N window", selected_commit_count: 4, baseline: "a".repeat(40), endpoint: "b".repeat(40) },
      { label: "1 day", selected_commit_count: 1, baseline: "c".repeat(40), endpoint: "d".repeat(40) },
    ],
    between_window_endpoints: {
      from: "b".repeat(40), to: "d".repeat(40), changes: [{ status: "M", new_path: "x.cpp" }], impact: "unknown",
      candidate_comparison: [
        { status: "new_candidate", detector_id: "d1", rule_id: "r1", file: "x.cpp", symbol: "f", before: [], after: [{ id: "1" }] },
        { status: "disappeared_candidate", detector_id: "d2", rule_id: "r2", file: "y.cpp", symbol: "g", before: [{ id: "2" }], after: [] },
        { status: "persistent_candidate", detector_id: "d3", rule_id: "r3", file: "z.cpp", symbol: "h", before: [{ id: "3" }], after: [{ id: "4" }] },
        { status: "unknown_detector_version_changed", detector_id: "d4", rule_id: "r4", file: "w.cpp", symbol: "i", before: [], after: [] },
      ],
    },
  });

  assert.equal(result.windows[0].label, "7 日窗口");
  assert.equal(result.windows[0].scanId, "n-after");
  assert.equal(result.windows[1].label, "最近 1 日窗口");
  assert.equal(result.betweenEndpoints.changedFileCount, 1);
  assert.deepEqual(result.counts, {
    new_candidate: 1, disappeared_candidate: 1, persistent_candidate: 1, unknown: 1,
  });
  assert.equal(result.impact, "unknown");
  assert.equal(result.validatedVulnerability, 0);
  assert.equal("vulnerability_introduced_or_fixed" in result, false);
});

test("blocked comparison keeps endpoint and candidate changes unknown", () => {
  const result = loadSummaryBuilder()({ status: "blocked", lookback_days: 3,
    scan_ids: ["a", "b", "c", "d"], impact: "unknown", validated_vulnerability: 0,
    reason: "An endpoint scan failed.",
    windows: [{ status: "unknown", candidate_comparison: [{ status: "unknown" }] }],
  });
  assert.equal(result.windows.length, 2);
  assert.equal(result.windows[0].endpoint, null);
  assert.equal(result.betweenEndpoints.from, null);
  assert.equal(result.comparisonAvailable, false);
  assert.equal(result.counts.unknown, null);
  assert.equal(result.reason, "An endpoint scan failed.");
  assert.equal(result.impact, "unknown");
  assert.equal(result.validatedVulnerability, 0);
});
