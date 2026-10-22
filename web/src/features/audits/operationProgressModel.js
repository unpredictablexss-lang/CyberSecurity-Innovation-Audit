const SHA256 = /^[a-f0-9]{64}$/i;
const COMMIT = /^[a-f0-9]{40}$/i;

export const JOINT_CANDIDATE_PREVIEW_PATH = "/operations/version-matrix-candidate-comparisons/preview";
export const JOINT_CANDIDATE_CREATE_PATH = "/operations/version-matrix-candidate-comparisons";
export const RECENT_JOINT_CANDIDATE_PREVIEW_PATH = "/operations/joint-candidate-comparisons/preview";
export const RECENT_JOINT_CANDIDATE_CREATE_PATH = "/operations/joint-candidate-comparisons";

export const REVIEW_STATUS_LABELS = Object.freeze({
  queued: "排队中", running: "运行中", completed: "已完成",
  completed_with_limitations: "已完成（存在限制）", failed: "失败",
  cancelled: "已取消", timed_out: "超时", interrupted: "中断", blocked: "受阻",
  not_triaged: "未研判", not_requested: "未请求", awaiting_r1: "等待 AI 初步分析",
  candidate_limit_reached: "超过授权名额", failed_selection: "候选选择失败",
  queue_limit_exceeded: "队列容量不足", revoked: "授权已撤销",
});

const ENDPOINT_STATE_LABELS = Object.freeze({
  static_only: "仅静态扫描，未请求模型", awaiting_static: "等待静态扫描",
  static_incomplete: "静态结果未完成", awaiting_individual_consent: "等待逐端点授权",
  completed_with_limitations: "授权范围内研判已返回（存在限制）",
  authorization_revoked: "外发授权已撤销", revoked: "外发授权已撤销",
  awaiting_model_schedule: "等待 Agent 排队", authorization_changed: "授权条件已变化",
  no_eligible_candidates: "没有符合条件的研判候选", completed: "授权范围内研判已完成",
  partially_completed: "部分完成，仍有候选未研判或调用失败", agent_in_progress: "智能研判中",
  queued: "Agent 任务排队中", running: "智能研判中", failed: "全部已选 Agent 调用均失败",
  cancelled: "Agent 任务已取消", not_triaged: "尚未研判", candidate_limit_exceeded: "超过端点候选保护上限",
  queue_limit_exceeded: "Agent 队列容量不足",
});

const PHASE_STATES = ["queued", "running", "completed", "completed_with_limitations", "failed", "cancelled", "timed_out", "interrupted", "blocked"];

function countValue(progress, status) {
  const explicit = progress?.[`${status}_count`];
  const fallback = progress?.status_counts?.[status];
  const value = Number.isSafeInteger(explicit) ? explicit : fallback;
  return Number.isSafeInteger(value) && value >= 0 ? value : 0;
}

function sha(value) { return typeof value === "string" && SHA256.test(value); }
function commit(value) { return typeof value === "string" && COMMIT.test(value); }

function phaseView(progress, operations, endpointCommit) {
  const source = progress && typeof progress === "object" ? progress : {};
  const children = Array.isArray(operations) ? operations : [];
  return {
    state: source.state || (children.length ? "unknown" : "not_triaged"),
    stateLabel: REVIEW_STATUS_LABELS[source.state] || source.state || "未研判",
    operationCount: Number.isSafeInteger(source.operation_count) ? source.operation_count : null,
    summariesReturned: Array.isArray(operations),
    counts: Object.fromEntries(PHASE_STATES.map((status) => [status, countValue(source, status)])),
    reasons: Array.isArray(source.failure_reasons) ? source.failure_reasons.map((item) => ({
      operationId: typeof item?.operation_id === "string" ? item.operation_id : null,
      candidateId: typeof item?.candidate_id === "string" ? item.candidate_id : null,
      status: typeof item?.status === "string" ? item.status : "unknown",
      statusLabel: REVIEW_STATUS_LABELS[item?.status] || item?.status || "未知",
      reason: typeof item?.reason === "string" ? item.reason : "未提供失败原因",
    })) : [],
    operations: children.map((item) => {
      const id = typeof item?.id === "string" ? item.id : null;
      const boundCommit = typeof item?.commit === "string" ? item.commit : null;
      const status = typeof item?.status === "string" ? item.status : null;
      const resultSha256 = sha(item?.result_sha256) ? item.result_sha256 : null;
      const reportSha256 = sha(item?.report_sha256) ? item.report_sha256 : null;
      const hasTerminalResult = status === "completed" || status === "completed_with_limitations";
      const hasExpectedResultBinding = !hasTerminalResult || Boolean(resultSha256 && reportSha256);
      const bindingIssue = !id ? "operation ID 未提供"
        : !status ? "子任务状态未提供"
          : !commit(endpointCommit) || boundCommit !== endpointCommit ? "固定端点 Commit 缺失或不一致"
            : hasTerminalResult && !resultSha256 ? "结束结果缺少有效 Result SHA-256"
              : hasTerminalResult && !reportSha256 ? "结束结果缺少有效源码 Report SHA-256"
                : null;
      const bindingValid = Boolean(id && status && hasExpectedResultBinding
        && commit(endpointCommit) && boundCommit === endpointCommit);
      return {
        id, status: status || "unknown",
        statusLabel: REVIEW_STATUS_LABELS[item?.status] || item?.status || "未知",
        commit: boundCommit, candidateId: typeof item?.candidate_id === "string" ? item.candidate_id : null,
        resultSha256, reportSha256,
        bindingValid, bindingIssue,
      };
    }),
  };
}

export function buildIntelligentReviewView(endpoint) {
  if (!endpoint || typeof endpoint !== "object") return null;
  const state = typeof endpoint.agent_status === "string" ? endpoint.agent_status : "not_triaged";
  const isStatic = state === "static_only";
  const r1 = phaseView(endpoint.r1_progress, endpoint.r1_operations, endpoint.commit);
  const r2 = phaseView(endpoint.r2_progress, endpoint.r2_operations, endpoint.commit);
  return {
    state, stateLabel: ENDPOINT_STATE_LABELS[state] || REVIEW_STATUS_LABELS[state] || state || "未知",
    stateTone: state === "completed" ? "success" : state === "failed" || state === "revoked" || state === "authorization_revoked" ? "error"
      : state === "partially_completed" || state === "completed_with_limitations" ? "warning" : "default",
    reason: typeof endpoint.triage_state_reason === "string" ? endpoint.triage_state_reason : null,
    candidateCount: Number.isSafeInteger(endpoint.candidate_count) ? endpoint.candidate_count : null,
    commit: typeof endpoint.commit === "string" ? endpoint.commit : null,
    scanId: typeof endpoint.scan_id === "string" ? endpoint.scan_id : null,
    r1, r2,
    isStatic,
    modelResultIsConfirmation: endpoint.model_result_is_product_vulnerability_confirmation === true,
  };
}

export function buildRecentWindowCandidatePairs(operation) {
  const endpoints = operation?.result?.between_window_endpoints;
  if (!endpoints || typeof endpoints !== "object") return [];
  return buildMatrixCandidatePairs({ result: { comparisons: [{
    from: endpoints.from,
    to: endpoints.to,
    candidate_comparison: endpoints.candidate_comparison,
  }] } });
}

export function buildMatrixCandidatePairs(operation) {
  const result = operation?.result;
  const comparisons = Array.isArray(result?.comparisons) ? result.comparisons : [];
  const pairs = [];
  comparisons.forEach((comparison, comparisonIndex) => {
    const groups = Array.isArray(comparison?.candidate_comparison) ? comparison.candidate_comparison : [];
    groups.forEach((group, groupIndex) => {
      const before = Array.isArray(group?.before) ? group.before : [];
      const after = Array.isArray(group?.after) ? group.after : [];
      const uniquePair = before.length === 1 && after.length === 1
        && typeof before[0]?.id === "string" && typeof after[0]?.id === "string";
      pairs.push({
        key: `${comparison?.from || ""}:${comparison?.to || ""}:${group?.detector_id || ""}:${group?.rule_id || ""}:${group?.file || ""}:${comparisonIndex}:${groupIndex}`,
        fromCommit: typeof comparison?.from === "string" ? comparison.from : null,
        toCommit: typeof comparison?.to === "string" ? comparison.to : null,
        status: typeof group?.status === "string" ? group.status : "unknown",
        matchBasis: typeof group?.match_basis === "string" ? group.match_basis : "unknown",
        file: typeof group?.file === "string" ? group.file : "未知文件",
        detectorId: typeof group?.detector_id === "string" ? group.detector_id : "未知检测器",
        ruleId: typeof group?.rule_id === "string" ? group.rule_id : "未知规则",
        fromCandidate: uniquePair ? before[0] : null,
        toCandidate: uniquePair ? after[0] : null,
        eligibleForPreview: uniquePair && COMMIT.test(comparison?.from || "") && COMMIT.test(comparison?.to || "")
          && comparison.from !== comparison.to,
      });
    });
  });
  return pairs;
}

function requiredText(value, label) {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${label} 缺失`);
  return value;
}

export function jointCandidatePreviewPayload(parentOperationId, pair, parentKind = "version_matrix") {
  if (!pair || !COMMIT.test(pair.fromCommit || "") || !COMMIT.test(pair.toCommit || "")
      || pair.fromCommit === pair.toCommit) throw new Error("必须选择两个不同的固定版本");
  const recentWindow = parentKind === "recent_window_comparison";
  return {
    [recentWindow ? "recent_window_operation_id" : "matrix_operation_id"]:
      requiredText(parentOperationId, recentWindow ? "时间窗口任务 ID" : "版本矩阵任务 ID"),
    from_commit: pair.fromCommit,
    from_candidate_id: requiredText(pair.fromCandidate?.id, "基准候选 ID"),
    to_commit: pair.toCommit,
    to_candidate_id: requiredText(pair.toCandidate?.id, "对比候选 ID"),
  };
}

export function jointCandidateCreatePayload(parentOperationId, pair, consent, parentKind = "version_matrix") {
  const preview = consent && typeof consent === "object" ? consent : {};
  return {
    ...jointCandidatePreviewPayload(parentOperationId, pair, parentKind),
    approved: true,
    consent_nonce: requiredText(preview.consent_nonce, "预览授权 nonce"),
    expected_consent_sha256: requiredText(preview.consent_sha256, "预览授权摘要"),
    expires_at: requiredText(preview.expires_at, "预览授权有效期"),
  };
}

export function buildJointEgressSummary(contextSummary) {
  const source = contextSummary && typeof contextSummary === "object" ? contextSummary : {};
  const evidenceProvided = Array.isArray(source.evidence_preview);
  const evidence = evidenceProvided ? source.evidence_preview : [];
  const manifest = source.linked_review_manifest && typeof source.linked_review_manifest === "object"
    ? source.linked_review_manifest : {};
  const fromProvided = Array.isArray(manifest.from);
  const toProvided = Array.isArray(manifest.to);
  const linkedReviewProvided = fromProvided && toProvided;
  return {
    evidenceProvided,
    evidenceCount: evidenceProvided ? evidence.length : null,
    sourceEvidenceCount: Number.isSafeInteger(source.source_evidence_count) ? source.source_evidence_count : null,
    fileCount: evidenceProvided ? new Set(evidence.map((item) => item?.file).filter((file) => typeof file === "string")).size : null,
    linkedReviewProvided,
    linkedReviewCount: linkedReviewProvided ? manifest.from.length + manifest.to.length : null,
    linkedReviewFromCount: fromProvided ? manifest.from.length : null,
    linkedReviewToCount: toProvided ? manifest.to.length : null,
  };
}
export function buildJointLinkedAgentChildrenView(contextSummary) {
  const source = contextSummary && typeof contextSummary === "object" ? contextSummary : {};
  const raw = source.linked_agent_children && typeof source.linked_agent_children === "object"
    ? source.linked_agent_children : {};
  const side = (name) => {
    const provided = Array.isArray(raw[name]);
    const items = provided ? raw[name].map((child) => {
      const id = typeof child?.operation_id === "string" ? child.operation_id : null;
      const status = typeof child?.status === "string" ? child.status : null;
      const resultSha256 = sha(child?.result_sha256) ? child.result_sha256 : null;
      const bindingIssue = !id ? "Agent 操作 ID 未提供" : !status ? "Agent 操作状态未提供"
        : status === "completed" && !resultSha256 ? "已完成结果的 SHA-256 未提供或无效" : null;
      return { id, status: status || "unknown", statusLabel: REVIEW_STATUS_LABELS[status] || status || "状态未知",
        resultSha256, bindingIssue, linkValid: Boolean(id && status && !(status === "completed" && !resultSha256)) };
    }) : [];
    return { provided, items };
  };
  return {
    resultCount: Number.isSafeInteger(source.linked_agent_result_count) ? source.linked_agent_result_count : null,
    from: side("from"), to: side("to"),
  };
}
