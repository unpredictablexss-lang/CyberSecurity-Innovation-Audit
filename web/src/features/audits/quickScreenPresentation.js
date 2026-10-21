import { chineseNarrative } from "../cases/chineseNarrativeText.js";
const assessmentLabels = {
  investigate: "建议继续深度调查",
  defer: "暂缓调查",
  possible_refutation: "发现待复核的反证线索",
  insufficient_context: "当前证据不足",
  quick_unknown: "研判结果未知",
};

const reviewStatusLabels = {
  model_unverified: "模型意见待人工核验",
};

const stateLabels = {
  queued: "排队中",
  running: "执行中",
  completed: "已完成",
  completed_with_limitations: "已完成（存在限制）",
  partial: "部分完成",
  quick_unknown: "结果未知",
  unknown: "未知",
};

const toolHintLabels = {
  find_callers: "查找调用位置",
  inspect_guard: "检查权限与边界校验",
  inspect_sink: "检查敏感操作点",
  inspect_source: "追查输入来源",
};

const budgetStateLabels = {
  active: "进行中",
  settled: "已结算",
  complete: "已完成",
  completed: "已完成",
  unavailable: "不可用",
  unknown: "未知",
};

const hasChinese = (value) => typeof value === "string" && value.trim().length > 0 && chineseNarrative(value).isChinese;

function listValue(value, kind) {
  if (!Array.isArray(value) || value.length === 0) return "无";
  const labels = kind === "tool" ? toolHintLabels : {};
  const localized = value.map((item) => labels[item] || (hasChinese(item) ? item : null));
  if (localized.every(Boolean)) return localized.join("、");
  return `共 ${value.length} 项，详细内容请展开下方“模型原文”查看`;
}

export function quickScreenPresentation(result = {}, requestState = "unknown") {
  const assessment = result.quick_assessment;
  const rationale = typeof result.rationale === "string" ? result.rationale.trim() : "";
  const reason = typeof result.reason_code === "string" ? result.reason_code.trim() : "";
  const chineseRationale = hasChinese(rationale);
  const chineseReason = hasChinese(reason);
  const reviewStatus = reviewStatusLabels[result.review_status] || "模型意见待核验";
  const detail = chineseRationale
    ? rationale
    : chineseReason
      ? reason
      : rationale || reason
        ? "模型已完成本轮初步研判，但详细说明以英文返回，原文已保留在下方“模型原文”中。该意见仅供人工复核，不代表漏洞已确认。"
        : "没有可复核的模型说明；候选仍待人工复核。模型意见不确认漏洞，也不代表源码安全。";

  return {
    assessment: assessmentLabels[assessment] || "研判结果待核对",
    reviewStatus,
    requestState: stateLabels[requestState] || "状态待核对",
    rationale: detail,
    missingEvidence: listValue(result.missing_obligations, "text"),
    nextSteps: listValue(result.next_tool_hints, "tool"),
    uncertainties: listValue(result.uncertainties, "text"),
    budgetState: budgetStateLabels[result.budget_state] || result.budget_state || "未知",
    hasEnglishOriginal: Boolean(
      (rationale && !chineseRationale) || (reason && !chineseReason)
        || [result.missing_obligations, result.uncertainties].some((items) =>
          Array.isArray(items) && items.some((item) => !hasChinese(item)))
    ),
  };
}

export function quickAssessmentLabel(value) {
  return assessmentLabels[value] || "建议待核对";
}

export function quickScreenStateLabel(value) {
  return stateLabels[value] || "状态未知";
}

export function modelReviewStatusLabel(value) {
  return reviewStatusLabels[value] || "模型意见待核验";
}

export function budgetStateLabel(value) {
  return budgetStateLabels[value] || "未知";
}

export function investigationStopReasonLabel(value) {
  const labels = {
    completed: "调查已完成",
    completed_with_limitations: "调查已结束，部分内容受限",
    user_cancelled: "用户已取消",
    cancelled: "用户已取消",
    provider_error: "模型服务请求失败",
    provider_quota_exhausted: "模型服务账户额度不足",
    no_new_evidence: "未发现新的可核查源码证据",
  };
  return labels[value] || (value ? "因技术原因停止，详情见原始记录" : "停止原因未知");
}

export function budgetEnforcementLabel(value) {
  const labels = {
    advisory_only: "仅记录实际用量",
    enforced: "平台执行预算限制",
    none: "平台未设置累计用量上限",
  };
  return labels[value] || "由模型服务商账户决定";
}
