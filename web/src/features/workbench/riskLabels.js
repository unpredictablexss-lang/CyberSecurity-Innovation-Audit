// Keep impact severity, evidence confidence, and verification independent.
const severityColorMap = Object.freeze({
  critical: "magenta", high: "red", medium: "orange", low: "blue",
  info: "default", unknown: "default",
});
const riskTierColorMap = Object.freeze({
  high_confidence_candidate: "gold", further_validation: "blue",
  unknown_source_binding: "default", low_priority_manual: "default",
});
const riskTierLabels = Object.freeze({
  high_confidence_candidate: "高可信候选",
  further_validation: "待验证候选",
  unknown_source_binding: "来源待核候选",
  low_priority_manual: "低优先级候选",
});
const humanReviewStatusLabels = Object.freeze({
  unassessed: "待人工复核",
  under_review: "人工复核中",
  plausible_unproven: "人工认为值得验证",
  likely_false_positive: "人工倾向误报（未确认）",
  refuted: "人工认为当前证据不支持",
});
const humanReviewStatusColors = Object.freeze({
  unassessed: "default",
  under_review: "processing",
  plausible_unproven: "orange",
  likely_false_positive: "blue",
  refuted: "default",
});
const severityLabels = Object.freeze({
  critical: "严重", high: "高危", medium: "中危",
  low: "低危", info: "提示", unknown: "未分级",
});

export function candidateSeverityLabel(severity) {
  return severityLabels[severity] || "未分级";
}
export function candidateSeverityColor(severity) {
  return severityColorMap[severity] || "default";
}
export function candidateConfidenceLabel(tier) {
  return riskTierLabels[tier] || "待验证候选";
}
export function candidateConfidenceColor(tier) {
  return riskTierColorMap[tier] || "default";
}
export function humanReviewStatusLabel(status) {
  return humanReviewStatusLabels[status] || "复核状态未知";
}
export function humanReviewStatusColor(status) {
  return humanReviewStatusColors[status] || "default";
}
export function candidateVerificationLabel(state) {
  // Cross-audit risk observations are never promoted by model confidence.
  return state === "confirmed" ? "已人工核实（请查看证明材料）" : "尚未确认";
}

export const triageStateLabels = Object.freeze({
  not_requested: "未请求模型", not_triaged: "未研判",
  waiting_for_authorization: "等待本次任务授权", waiting_for_scan: "等待静态扫描",
  not_started: "尚未开始", unresolved: "未完成模型研判", selected: "已选入队列",
  not_selected: "未选入本轮", queued: "排队中", running: "处理中", in_progress: "处理中",
  stopping: "正在停止", cancelled: "已停止", completed: "已完成",
  completed_with_limitations: "完成但有限制", partially_completed: "部分完成",
  blocked: "受阻", blocked_authorization_changed: "授权已变化，已阻止",
  no_eligible_candidates: "没有符合条件的候选", stopped: "授权已撤销",
  failed: "失败", timed_out: "超时", interrupted: "中断",
  awaiting_r1: "等待首轮研判", budget_limited: "已达到候选授权名额",
  candidate_limit_exceeded: "候选数超过端点保护上限", queue_limit_exceeded: "队列容量不足；候选未研判",
  not_needed: "无需补充核查", failed_selection: "未能选择补充核查",
});

const scanStageLabels = Object.freeze({
  queued: "等待扫描", worker_started: "扫描 Worker 已启动",
  agent_review_queued: "扫描已完成；候选等待你决定是否授权研判",
  agent_review_not_required: "扫描已完成；没有候选需要模型研判",
  agent_review_queue_enqueue_failed: "静态报告已保存；研判任务未能排队",
  completed: "扫描已完成", completed_with_limitations: "扫描完成，存在覆盖限制",
  failed: "扫描失败", blocked: "扫描受阻", cancelled: "扫描已取消",
  interrupted: "扫描中断", timed_out: "扫描超时",
});

const analysisStatusLabels = Object.freeze({
  analyzed: "静态检查完成", partial: "部分检查", not_analyzed: "未检查",
  failed: "检查失败", unknown: "未知（待核实）",
});
const coverageStatusLabels = Object.freeze({
  complete: "完整覆盖", completed: "执行完成",
  completed_with_limitations: "完成但存在覆盖限制", partial: "部分覆盖",
  blocked: "受阻", failed: "执行失败", not_analyzed: "未分析",
  unknown: "未知（待核实）",
});

const agentVerdictLabels = Object.freeze({
  confirmed: "源码证据门通过（产品状态仍未知）",
  false_positive: "源码证据支持误报解释（仍需人工复核）",
  likely_true_positive: "模型倾向漏洞候选",
  likely_false_positive: "模型倾向误报",
  needs_more_evidence: "需要更多证据",
  unknown: "未知（待核实）",
  analysis_failed: "分析失败",
});
const agentConfidenceLabels = Object.freeze({
  high: "高（模型自评）", medium: "中（模型自评）",
  low: "低（模型自评）", none: "无",
});
const agentScopeLabels = Object.freeze({ fixed_source_code: "本次扫描源码", none: "未完成源码验证" });
const productStatusLabels = Object.freeze({
  unknown: "未知（待核实）", candidate: "待复核候选",
  confirmed: "已确认（请核对产品验证证据）",
});
const agentVerdictReasons = Object.freeze({
  "The structured Agent answer did not pass server validation.": "结构化模型回答未通过服务端校验。",
  "All source-review obligations have cited support and no unsupported claims remain.": "所有源码复核义务均有引用支持，且没有未支持陈述；这只说明源码分诊门通过，产品状态仍未知。",
  "The model favors the vulnerability hypothesis, but source evidence is incomplete or mixed.": "模型倾向漏洞假设，但源码证据不完整或相互混合。",
  "All source-review obligations contain cited contrary evidence.": "所有源码复核义务均有带引用的相反证据；仍需人工复核。",
  "The model favors a false-positive explanation, but source evidence is incomplete or mixed.": "模型倾向误报解释，但源码证据不完整或相互混合。",
  "The available fixed-source evidence does not support a stronger Agent verdict.": "当前扫描源码证据不足以支持更强的模型分诊结论。",
});

const groupingBasisLabels = Object.freeze({
  "same detector/version, rule, file, symbol, and source hash":
    "仓库快照、Detector 版本、规则、文件、符号和源码哈希均一致",
});

const obligationKindLabels = Object.freeze({
  callee_binding: "调用目标与实现",
  sink_behavior: "敏感数据处理方式",
  runtime_log_visibility: "运行时日志可见性",
  security_impact: "安全影响",
});

const obligationStatusLabels = Object.freeze({
  unknown: "未知（待核实）",
  unresolved: "尚未解决",
  evidence_found: "存在相关证据（仍需人工复核）",
  contrary_evidence: "存在相反证据（仍需人工复核）",
});

const obligationDescriptionTranslations = Object.freeze({
  "Resolve the exact overload, receiver, and implementation for AuthSessionSaveSessionKey.":
    "确认 AuthSessionSaveSessionKey 对应的具体重载、接收对象及实现。",
  "Determine whether the callee logs, serializes, stores, or safely transforms the sensitive value.":
    "确认被调函数会记录、序列化、存储该敏感值，还是进行了安全转换。",
  "No log exposure or reader reachability is established by this call alone.":
    "仅凭此调用无法证明存在日志泄露或可触达的读取方。",
  "Establish recoverable sensitive material and concrete impact independently.":
    "独立确认敏感材料能否被恢复，以及具体安全影响。",
});

export function agentVerdictLabel(status) {
  return agentVerdictLabels[status] || "未知（待核实）";
}
export function agentConfidenceLabel(confidence) {
  return agentConfidenceLabels[confidence] || "未提供";
}
export function agentScopeLabel(scope) {
  return agentScopeLabels[scope] || "范围未知";
}
export function productStatusLabel(status) {
  return productStatusLabels[status] || "未知（待核实）";
}
export function agentVerdictReasonLabel(reason) {
  return agentVerdictReasons[reason] || reason || "结果尚未通过服务端校验。";
}
export function analysisStatusLabel(status) {
  return analysisStatusLabels[status] || "未知（待核实）";
}
export function coverageStatusLabel(status) {
  return coverageStatusLabels[status] || "未知（待核实）";
}
export function groupingBasisLabel(basis) {
  return groupingBasisLabels[basis] || "按报告记录的字段分组";
}
export function groupingSymbolLabel(symbol) {
  return symbol || "未识别符号";
}
export function coverageSummaryLabel(parsing, unclaimedFiles) {
  const count = (value) => Number.isInteger(value) && value >= 0 ? value + " 个" : "未知";
  const source = parsing && typeof parsing === "object" ? parsing : {};
  return "解析覆盖：完整 " + count(source.complete) + "、部分 " + count(source.partial)
    + "、失败 " + count(source.failed) + "、未运行 " + count(source.not_run)
    + "；未被检测器认领 " + count(unclaimedFiles) + "。";
}
export function obligationKindLabel(kind) {
  return obligationKindLabels[kind] || (kind ? "核查项：" + kind : "未命名核查项");
}
export function obligationStatusLabel(status) {
  return obligationStatusLabels[status] || "状态未知";
}
export function obligationDescriptionLabel(description) {
  return obligationDescriptionTranslations[description] || description || "报告未提供核查说明。";
}

const reportLimitations = Object.freeze({
  "Diagnostics are candidates/evidence only, not proof of security impact.":
    "检测结果只代表待复核候选与证据，不构成安全影响证明。",
  "Zero diagnostics does NOT mean the component is free of vulnerabilities.":
    "零条候选不代表组件不存在漏洞。",
  "Git origin name is user declared; source is pinned local objects, not an OH product build.":
    "Git 远端名称由用户声明；扫描绑定的是本地 Git 对象版本，不是 OpenHarmony 产品构建产物。",
  "No compilation flags/macros, symbolic execution, hard plugin timeout or runtime validation.":
    "未纳入构建参数与宏定义，也未执行符号执行或运行时验证；检测器进程级硬超时隔离尚未实现。",
});
export function reportLimitationLabel(value) {
  return reportLimitations[value] || value || "报告未提供限制说明。";
}

const riskReasons = Object.freeze({
  "candidate source identity does not match the immutable report inventory":
    "候选来源与扫描报告清单不一致，需要重新核对。",
  "a human marked this item as refuted or low-priority; this is not a safety verdict":
    "人工将此项标为驳回或低优先级；这不代表已证明安全。",
  "fixed source/report hashes match and every recorded obligation has a quoted R0 evidence_found review":
    "本次扫描源码与报告哈希一致，且已逐项完成 人工源码引用复核；结论仍为候选。",
  "candidate analysis is partial or unknown": "候选分析不完整或状态未知。",
  "no complete evidence-obligation set is available": "尚无完整的证据义务清单。",
  "no complete quoted static-human evidence review is recorded": "尚未完成带源码引用的静态人工复核。",
  "static-human review did not meet the high-priority gate": "静态人工复核未达到高优先级门槛。",
  "one or more evidence obligations remain contrary or unresolved": "仍有证据义务尚未解决，或存在相反证据。",
  "additional independent validation remains necessary": "还需要独立复核或适用的运行时验证。",
});

export function triageStateLabel(state) {
  return triageStateLabels[state] || "状态未知";
}
export function taskReportStatusLabel(summary, job) {
  const status = summary?.report_status;
  if (status === "ready") return "已生成";
  if (status === "ready_with_limitations") return "已生成，存在覆盖限制";
  if (status === "available") return "报告已发布，扫描状态异常";
  if (status) return "状态未知";
  if (job?.report_sha256) return "正在读取报告状态";
  return "等待报告";
}
export function taskTriageStatusLabel(summary, job) {
  const state = summary?.triage_status || summary?.triage_progress?.state || summary?.state;
  if (state) return triageStateLabel(state);
  if (summary) return "状态未知";
  if (job?.report_sha256) return "正在读取研判状态";
  if (job?.status === "queued" || job?.status === "running") return "等待静态扫描报告";
  if (job?.status === "failed" || job?.status === "cancelled" || job?.status === "canceled") {
    return "静态扫描未生成可用报告，研判未启动";
  }
  return "状态未知";
}
export function scanStageLabel(stage) {
  return scanStageLabels[stage] || (stage ? "阶段详情请查看执行轨迹" : "阶段未知");
}
export function riskReasonLabel(reason) {
  return riskReasons[reason] || "需要进一步核对本项证据。";
}
export function riskReasonsLabel(reasons) {
  const labels = (Array.isArray(reasons) ? reasons : [])
    .map(riskReasonLabel)
    .map((label) => label.replace(/[。；;，,\s]+$/u, ""));
  return labels.length ? labels.join("；") + "。" : "需要进一步核对本项证据。";
}
export function highConfidenceAiSummary(summary) {
  if (typeof summary === "string" && summary.trim()) {
    return { state: "available", text: summary.trim() };
  }
  return {
    state: "unknown",
    text: "AI 摘要不可用；页面不推测模型理由，请依据本次扫描源码证据人工复核。",
  };
}
