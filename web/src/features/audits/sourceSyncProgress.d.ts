export type SourceSyncOperation = {
  status?: string;
  error?: string;
  spec?: { name?: string; url?: string };
  result?: {
    status?: string;
    error?: string;
    scan_error?: string;
    scan_status?: string;
    repository?: { name?: string };
    local_head_after_sync?: string;
    advertised_remote_refs?: unknown[];
    scan_job_id?: string;
    scan_commit?: string;
    limitations?: string[];
  };
  events?: Array<{ stage?: string }>;
};

export type SourceSyncScanJob = {
  status?: string;
  spec?: { commit?: string };
  report_sha256?: string;
} | null;

export type SourceSyncScanState = {
  loading?: boolean;
  error?: string;
};

export function sourceSyncSummary(
  operation: SourceSyncOperation | null | undefined,
  scanJob?: SourceSyncScanJob,
  scanState?: SourceSyncScanState,
): {
  repository: string;
  syncStatus: string;
  syncLabel: string;
  localHead: string | null;
  remoteRefCount: number | null;
  scanId: string;
  scanStatus: string;
  scanCommit: string | null;
  scanReportAvailable: boolean;
  scanError: string;
  syncError: string;
  scanQueueError: string;
  limitations: string[];
};
export function sourceSyncRetryAction(
  operation: SourceSyncOperation | null | undefined,
  scanJob?: SourceSyncScanJob,
): "sync" | "scan" | null;
export function sourceSyncBatchRetryAction(row: {
  status?: string;
  scanAfterSync?: boolean;
  scanStatus?: string;
  scanJobId?: string | null;
  error?: string;
} | null | undefined): "sync" | "scan" | null;
export function sourceSyncBatchRows(
  operation: Record<string, any> | null | undefined,
  scanJobs?: Record<string, any>,
): Array<{
  index: number;
  repository: string;
  status: string;
  scanAfterSync: boolean;
  scanStatus: string;
  scanJobId: string | null;
  scanCommit: string | null;
  localHead: string | null;
  error: string;
  duplicateOf: number | null;
}>;
