const syncLabels = {
  queued: "等待同步",
  running: "同步处理中",
  completed: "同步完成",
  completed_with_limitations: "同步完成（有限制）",
  failed: "同步失败",
  timed_out: "同步超时",
  interrupted: "同步中断",
  cancelled: "已取消",
};

export function sourceSyncSummary(operation, scanJob = null, scanState = {}) {
  const result = operation?.result || {};
  const events = Array.isArray(operation?.events) ? operation.events : [];
  const status = operation?.status || "unknown";
  const started = events.some((event) => event?.stage === "git_sync");
  const syncLabel = status === "running"
    ? (started ? "正在同步 Git 对象" : "准备开始同步")
    : (syncLabels[status] || "同步状态未知");
  const scanId = typeof result.scan_job_id === "string" ? result.scan_job_id : "";
  const scanStatus = !scanId
    ? "not_requested"
    : scanState.error
      ? "unavailable"
      : scanState.loading
        ? "loading"
        : (typeof scanJob?.status === "string" ? scanJob.status : "unknown");

  return {
    repository: result.repository?.name || operation?.spec?.name || "未知仓库",
    syncStatus: status,
    syncLabel,
    localHead: typeof result.local_head_after_sync === "string" ? result.local_head_after_sync : null,
    remoteRefCount: Array.isArray(result.advertised_remote_refs)
      ? result.advertised_remote_refs.length
      : null,
    scanId,
    scanStatus,
    scanCommit: scanJob?.spec?.commit || result.scan_commit || null,
    scanReportAvailable: Boolean(scanJob?.report_sha256),
    scanError: scanState.error || "",
    limitations: Array.isArray(result.limitations) ? result.limitations : [],
  };
}

/**
 * Build a per-repository progress view from operation events/result.
 * The batch rows intentionally expose repository names and immutable SHAs,
 * never host-local cache paths or Git command details.
 */
export function sourceSyncBatchRows(operation, scanJobs = {}) {
  const entries = Array.isArray(operation?.spec?.repositories) ? operation.spec.repositories : [];
  const rows = entries.map((entry, index) => ({
    index: index + 1,
    repository: entry?.name || "unknown repository",
    status: operation?.status === "queued" ? "queued" : "not_started",
    scanAfterSync: entry?.scan_after_sync === true,
    scanStatus: entry?.scan_after_sync === true ? "not_started" : "not_requested",
    scanJobId: null,
    scanCommit: null,
    localHead: null,
    error: "",
    duplicateOf: null,
  }));

  const apply = (index, payload, stage) => {
    const row = rows[index - 1];
    if (!row) return;
    if (payload && typeof payload === "object") {
      if (typeof payload.repository === "string") row.repository = payload.repository;
      if (typeof payload.status === "string") row.status = payload.status;
      if (typeof payload.scan_status === "string") row.scanStatus = payload.scan_status;
      if (typeof payload.scan_job_id === "string") row.scanJobId = payload.scan_job_id;
      if (typeof payload.scan_commit === "string") row.scanCommit = payload.scan_commit;
      if (typeof payload.local_head_after_sync === "string") row.localHead = payload.local_head_after_sync;
      if (typeof payload.error === "string") row.error = payload.error;
      if (Number.isInteger(payload.duplicate_of)) row.duplicateOf = payload.duplicate_of;
    }
    if (stage === "source_sync_batch_item_started") row.status = "running";
  };

  for (const event of Array.isArray(operation?.events) ? operation.events : []) {
    if (!String(event?.stage || "").startsWith("source_sync_batch_item_")) continue;
    let payload;
    try { payload = JSON.parse(event.message || "{}"); } catch { payload = {}; }
    if (Number.isInteger(payload.index)) apply(payload.index, payload, event.stage);
  }

  const results = Array.isArray(operation?.result?.repositories) ? operation.result.repositories : [];
  results.forEach((result, index) => apply(index + 1, result));

  for (const row of rows) {
    const job = row.scanJobId ? scanJobs[row.scanJobId] : null;
    if (job && typeof job.status === "string") row.scanStatus = job.status;
    if (job?.spec?.commit) row.scanCommit = job.spec.commit;
  }
  return rows;
}
