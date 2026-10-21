const text = (value) => typeof value === "string" ? value.trim() : "";
const rawString = (value) => typeof value === "string" ? value : "";
const isRecord = (value) => Boolean(value) && typeof value === "object" && !Array.isArray(value);
const stringList = (value) => Array.isArray(value)
  ? value.filter((item) => typeof item === "string" && item.trim()).map((item) => item.trim())
  : [];

function citationView(value) {
  if (typeof value === "string") {
    const displayText = value.trim();
    return displayText ? { displayText, evidenceId: "", location: "", quote: "", raw: value } : null;
  }
  if (!isRecord(value) || Object.keys(value).length === 0) return null;
  const evidenceId = text(value.evidence_id);
  const file = text(value.file);
  const start = Number.isInteger(value.line_start) ? value.line_start : null;
  const end = Number.isInteger(value.line_end) ? value.line_end : null;
  let location = file;
  if (file && start !== null) {
    location += ":" + start;
    if (end !== null && end !== start) location += "–" + end;
  }
  return {
    displayText: "",
    evidenceId,
    location,
    quote: rawString(value.quote),
    raw: value,
  };
}

function citationList(value) {
  if (!Array.isArray(value)) return [];
  return value.map(citationView).filter(Boolean);
}

function normalizeVulnerabilityReport(value) {
  if (!isRecord(value)) return null;
  const report = {
    title: text(value.title),
    summary: text(value.summary),
    rootCause: text(value.root_cause),
    impact: text(value.impact),
    preconditions: stringList(value.preconditions),
    attackPath: stringList(value.attack_path),
    remediation: text(value.remediation),
    citations: citationList(value.citations),
    boundary: "智能调查辅助分析 · 候选 / 未知 · 待人工复核",
  };
  const hasContent = Boolean(report.title || report.summary || report.rootCause || report.impact
    || report.preconditions.length || report.attackPath.length || report.remediation || report.citations.length);
  return hasContent ? report : null;
}

const POC_STATUS_LABELS = {
  draft_unexecuted: "待人工审查的草案",
  insufficient_evidence: "证据不足",
};

const ARTIFACT_STAGE_LABELS = {
  completed: "阶段已完成",
  running: "进行中",
  not_authorized: "未授权",
  not_applicable_single_shot: "未运行（单次模式不适用）",
  not_run_primary_answer_unavailable: "未运行（主分诊结果不可用）",
  incomplete: "失败 / 中断（生成未完成）",
  rejected: "失败（结果未通过校验）",
  failed: "失败",
  interrupted: "已中断",
};

function artifactItemStatus(stageStatus, itemStatus, kind) {
  if (stageStatus !== "completed") {
    return ARTIFACT_STAGE_LABELS[stageStatus] || "未知或未记录";
  }
  if (itemStatus === "insufficient_evidence") return "证据不足";
  if (kind === "report" && itemStatus === "draft_unverified") return "已生成（未验证）";
  if (kind === "poc" && itemStatus === "draft_unexecuted") return "已生成（草案未执行）";
  return "未记录";
}

function normalizeArtifactGeneration(value, reportValue, pocValue) {
  if (!isRecord(value) || Object.keys(value).length === 0) return null;
  const status = text(value.status);
  const callsUsed = Number.isInteger(value.calls_used) && value.calls_used >= 0
    ? value.calls_used
    : null;
  const maximumModelCalls = Number.isInteger(value.maximum_model_calls) && value.maximum_model_calls >= 0
    ? value.maximum_model_calls
    : null;
  return {
    status,
    statusLabel: ARTIFACT_STAGE_LABELS[status] || "未知或未记录",
    reportStatusLabel: artifactItemStatus(status,
      isRecord(reportValue) ? text(reportValue.status) : "", "report"),
    pocStatusLabel: artifactItemStatus(status,
      isRecord(pocValue) ? text(pocValue.status) : "", "poc"),
    callsUsed,
    maximumModelCalls,
  };
}

function normalizePocDraft(value) {
  if (!isRecord(value)) return null;
  const status = text(value.status);
  const draft = {
    status,
    statusLabel: POC_STATUS_LABELS[status] || "状态待确认",
    title: text(value.title),
    language: text(value.language),
    code: rawString(value.code),
    prerequisites: stringList(value.prerequisites),
    runSteps: stringList(value.run_steps),
    expectedObservation: text(value.expected_observation),
    negativeControl: text(value.negative_control),
    citations: citationList(value.citations),
    boundary: "智能调查草案 · 未执行 · 未验证 · 候选 / 未知",
  };
  const hasContent = Boolean(draft.status || draft.title || draft.language || draft.code.trim()
    || draft.prerequisites.length || draft.runSteps.length || draft.expectedObservation
    || draft.negativeControl || draft.citations.length);
  return hasContent ? draft : null;
}

export function buildAgentReportView(agentTriage = {}) {
  const triage = isRecord(agentTriage) ? agentTriage : {};
  return {
    vulnerabilityReport: normalizeVulnerabilityReport(triage.vulnerability_report),
    pocDraft: normalizePocDraft(triage.poc_draft),
    artifactGeneration: normalizeArtifactGeneration(
      triage.artifact_generation, triage.vulnerability_report, triage.poc_draft),
  };
}

export function buildAgentOperationArtifactView(operationResult = {}) {
  const result = isRecord(operationResult) ? operationResult : {};
  const assessment = isRecord(result.agent_assessment) ? result.agent_assessment : {};
  return buildAgentReportView({
    ...assessment,
    artifact_generation: result.artifact_generation,
  });
}
