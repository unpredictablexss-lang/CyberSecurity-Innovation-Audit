import test from "node:test";
import assert from "node:assert/strict";
import { sourceSyncSummary } from "../src/features/audits/sourceSyncProgress.js";

test("source sync shows queued state without claiming a scan was requested", () => {
  const summary = sourceSyncSummary({
    kind: "source_sync",
    status: "queued",
    spec: { name: "openharmony/sample" },
  });

  assert.equal(summary.repository, "openharmony/sample");
  assert.equal(summary.syncLabel, "等待同步");
  assert.equal(summary.scanStatus, "not_requested");
  assert.equal(summary.scanReportAvailable, false);
});

test("source sync reports the Git phase while the handler is running", () => {
  const summary = sourceSyncSummary({
    status: "running",
    events: [{ stage: "queued" }, { stage: "git_sync" }],
  });

  assert.equal(summary.syncLabel, "正在同步 Git 对象");
});

test("source sync uses live scan status instead of the stale enqueue snapshot", () => {
  const summary = sourceSyncSummary({
    kind: "source_sync",
    status: "completed",
    spec: { name: "openharmony/sample" },
    events: [],
    result: {
      repository: { name: "openharmony/sample", path: "/private/server/path" },
      local_head_after_sync: "a".repeat(40),
      advertised_remote_refs: [{ ref: "refs/remotes/origin/main" }],
      scan_job_id: "b".repeat(32),
      scan_commit: "c".repeat(40),
      scan_status: "queued",
    },
  }, {
    status: "completed_with_limitations",
    spec: { commit: "d".repeat(40) },
    report_sha256: "e".repeat(64),
  });

  assert.equal(summary.syncLabel, "同步完成");
  assert.equal(summary.localHead, "a".repeat(40));
  assert.equal(summary.remoteRefCount, 1);
  assert.equal(summary.scanStatus, "completed_with_limitations");
  assert.equal(summary.scanCommit, "d".repeat(40));
  assert.equal(summary.scanReportAvailable, true);
  assert.equal(Object.hasOwn(summary, "path"), false);
  assert.equal(JSON.stringify(summary).includes("/private/server/path"), false);
  assert.equal(JSON.stringify(summary).includes("scan_status"), false);
});

test("source sync exposes scan-status read failures rather than presenting a stale queued state", () => {
  const summary = sourceSyncSummary({
    status: "completed",
    result: { scan_job_id: "b".repeat(32), scan_status: "queued" },
  }, null, { error: "network unavailable" });

  assert.equal(summary.scanStatus, "unavailable");
  assert.equal(summary.scanError, "network unavailable");
});
