import test from "node:test";
import assert from "node:assert/strict";
import { sourceSyncBatchRows } from "../src/features/audits/sourceSyncProgress.js";

test("batch rows show per-repository running and failure events", () => {
  const rows = sourceSyncBatchRows({
    status: "running",
    spec: { repositories: [
      { name: "openharmony/alpha", scan_after_sync: true },
      { name: "openharmony/beta", scan_after_sync: false },
    ] },
    events: [
      { stage: "source_sync_batch_item_started", message: JSON.stringify({ index: 1, repository: "openharmony/alpha" }) },
      { stage: "source_sync_batch_item_failed", message: JSON.stringify({ index: 2, repository: "openharmony/beta", status: "failed", error: "transfer failed" }) },
    ],
  });
  assert.equal(rows[0].status, "running");
  assert.equal(rows[0].scanStatus, "not_started");
  assert.equal(rows[1].status, "failed");
  assert.equal(rows[1].error, "transfer failed");
});

test("batch result overrides progress and attaches live pinned scan status", () => {
  const operation = {
    status: "completed_with_limitations",
    spec: { repositories: [
      { name: "openharmony/alpha", scan_after_sync: true },
      { name: "openharmony/alpha", scan_after_sync: true },
    ] },
    events: [{ stage: "source_sync_batch_item_started", message: JSON.stringify({ index: 1 }) }],
    result: { repositories: [
      { repository: "openharmony/alpha", status: "completed", scan_status: "queued",
        scan_job_id: "scan-1", scan_commit: "a".repeat(40), local_head_after_sync: "b".repeat(40) },
      { repository: "openharmony/alpha", status: "skipped_duplicate", duplicate_of: 1,
        scan_status: "not_started" },
    ] },
  };
  const rows = sourceSyncBatchRows(operation, {
    "scan-1": { status: "completed_with_limitations", spec: { commit: "c".repeat(40) } },
  });
  assert.equal(rows[0].status, "completed");
  assert.equal(rows[0].scanStatus, "completed_with_limitations");
  assert.equal(rows[0].scanCommit, "c".repeat(40));
  assert.equal(rows[0].localHead, "b".repeat(40));
  assert.equal(rows[1].status, "skipped_duplicate");
  assert.equal(rows[1].duplicateOf, 1);
  assert.equal(JSON.stringify(rows).includes("/private/server/path"), false);
});
