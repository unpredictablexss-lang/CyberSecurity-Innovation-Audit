const rejectionDescriptions = {
  invalid_schema: "模型返回的 JSON 顶层字段缺失、多余或命名不符；无法作为调查结论接收。系统已拒收该答复，候选仍待复核。",
  invalid_claim_structure: "模型支持性主张的结构错误：每条主张必须同时包含 claim、obligation_indices 和 citations，不能缺项或自行增加字段。",
  invalid_obligation_mapping: "模型引用的证据义务编号重复、越界或未正确绑定主张，服务端已拒收答复。",
  incomplete_obligation_reviews: "模型没有逐项且仅一次地回答全部证据义务，服务端已拒收不完整的结构化答复。",
  invalid_obligation_review: "模型返回的证据义务复核字段或分诊状态不符合要求，服务端已拒收答复。",
  missing_source_citations: "模型主张缺少必要的固定源码引文，或引文数量超出结构限制，服务端已拒收答复。",
  unsupported_verdict: "模型给出了倾向真阳性或误报的结论，但没有相应的带源码引文的支持性主张，服务端已拒收该结论。",
  invalid_summary: "模型摘要的类型或长度不符合调查结果格式，服务端已拒收答复。",

  invalid_source_line_range: "模型引用的行号未通过校验：每条引文必须属于同一证据 ID 和文件，覆盖最多连续 8 行、原文 8–500 字符，并位于已读取源码范围内。系统拒收了该答复，候选仍待复核。",
  unresolved_authorization_policy_claim: "模型试图用支持性主张关闭仍需人工复核的调用方授权策略义务。服务端已拒绝并丢弃答复，所有义务仍保持未决。",
  unresolved_authorization_policy_suppression: "模型试图在授权策略仍未决时将候选判为倾向误报。服务端已拒绝并丢弃答复，所有义务仍保持未决。",
  human_runtime_claim_mapping: "模型主张引用了仅能由人工或运行时检查的义务。服务端已拒绝并丢弃答复，所有义务仍保持未决。",
  human_runtime_obligation_mapped: "模型为仅能由人工或运行时检查的义务提供了分诊标签。服务端已拒绝并丢弃答复，所有义务仍保持未决。",
  invalid_json: "最终答复未通过 JSON 解析。系统已丢弃模型主张，并将所有义务保持未决。",
};

const skepticDescriptions = {
  invalid_skeptic_response: "独立复核模型的答复未通过结构或证据校验，主分析结论未被接收。旧记录没有保存更细的失败项。",
  skeptic_invalid_json: "独立复核答复不是有效 JSON。",
  skeptic_invalid_schema: "独立复核 JSON 必须只包含 reviews，复核条目字段必须符合约定。",
  skeptic_incomplete_reviews: "独立复核未逐项且仅一次地回答全部核查项。",
  skeptic_invalid_review: "独立复核条目的字段或 result 状态枚举不符合要求。",
  skeptic_invalid_indices: "独立复核的核查项编号重复或越界。",
  skeptic_human_runtime_verdict: "独立复核对只能人工或运行时验证的事项给出了源码无法支持的结论。",
  skeptic_missing_citation: "独立复核提出反证，但没有提供固定源码引用。",
  skeptic_unexpected_citation: "独立复核为 unknown 或未观察到反证的状态附加了引用；约定仅允许反证候选携带引用。",
  skeptic_citation_limit: "独立复核每个核查项的引用超过 4 条。",
  skeptic_invalid_citation: "独立复核的证据 ID、文件或引用字段不符合要求。",
  skeptic_invalid_source_range: "独立复核引用超出已提供源码范围，或超过连续 8 行、原文 8–500 字符。",
  provider_or_budget_error: "独立复核请求发生 Provider 或请求预算异常，未取得可接收的复核结果。",
  provider_incomplete: "独立复核模型响应未完整结束。",
  timeout_budget_exhausted: "独立复核开始前已用完本任务授权的时间。",
  shared_auxiliary_call_reserve_exhausted: "独立复核开始前已用完本任务授权的调用次数。",
};

function diagnosticDetails(diagnostic) {
  if (!Array.isArray(diagnostic?.issues)) return "";
  return diagnostic.issues.slice(0, 12).map(issue => {
    const path = typeof issue?.path === "string" ? issue.path : "$";
    if (issue.kind === "object_keys") return `${path}：缺少 ${issue.missing?.join("、") || "无"}；多余字段 ${issue.unexpected_field_count || 0} 个`;
    if (issue.kind === "source_range") return `${path}：引用必须属于实际提供的同一证据和文件，连续 1–8 行、原文 8–500 字符`;
    if (issue.kind === "enum") return `${path}：状态必须使用 ${issue.allowed?.join(" / ")}`;
    return "";
  }).filter(Boolean).join("；");
}

export function structuredAnswerRejection(status, errorCode, diagnostic) {
  if (typeof status === "string" && status.startsWith("skeptic_")) {
    const code = diagnostic?.code || errorCode;
    const description = skepticDescriptions[code] || "独立复核未完成，主分析结论未被接收；候选仍待复核。";
    return description + "（原因码：" + (code || "skeptic_incomplete") + "）" + diagnosticDetails(diagnostic);
  }
  if (status === "provider_incomplete") {
    if (errorCode === "max_output_tokens") {
      return "Provider 响应达到本次单请求输出 token 上限；服务端已丢弃不完整答复，所有证据义务仍保持未决。若要调整单次上限后重试，请重新预览并单独授权；本次结果不代表候选误报或安全。";
    }
    if (errorCode === "provider_request_outcome_unknown") return "模型请求已发出，但没有取得可确认的完整响应，调用结果和该次用量无法确定。不能据此断言超时或 Token 用尽；请核对 Provider 状态后重新预览授权。";
    if (errorCode === "per_request_timeout") return "模型单次请求超时，未取得完整响应；候选仍待复核。";
    if (errorCode === "per_request_context_limit") return "待发送上下文超过单次输入限制，请缩小源码范围；候选仍待复核。";
    return "Provider 响应未完整结束；服务端已丢弃不完整答复，所有证据义务仍保持未决。核对任务状态后如需重试，请重新预览并单独授权；本次结果不代表候选误报或安全。";
  }
  if (typeof status !== "string" || !status.startsWith("rejected_")) return null;
  const code = typeof errorCode === "string" ? errorCode : "";
  const description = rejectionDescriptions[code]
    || "最终结构化答复未通过服务端的结构、引用或策略校验。系统已丢弃模型主张，并将所有义务保持未决；当前“未知”结果不构成漏洞判断。";
  return description + (code ? "（原因码：" + code + "）" : "") + diagnosticDetails(diagnostic);
}


export function artifactFailureMessage(artifact) {
  if (!["incomplete", "rejected"].includes(artifact?.status)) return null;
  const descriptions = {
    artifact_invalid_json: "报告 / PoC 草稿不是有效 JSON。",
    artifact_invalid_schema: "报告 / PoC 草稿的结构字段不符合要求。",
    artifact_inventory_unavailable: "固定版本源码清单不可用，草稿引用无法校验。",
    artifact_citation_outside_inventory: "报告 / PoC 草稿引用不属于本任务固定源码清单或授权路径，已拒收草稿。",
    artifact_citation_not_supplied: "报告 / PoC 草稿引用不是本次提供的固定源码证据，已拒收草稿。",
    artifact_invalid_source_range: "报告 / PoC 草稿引用行范围不合法，已拒收草稿。",
    artifact_narrative_not_chinese: "报告 / PoC 草稿未按要求提供中文说明，已拒收草稿。",
    max_output_tokens: "报告 / PoC 草稿的单次响应达到输出上限。",
  };
  return "主分析与复核已通过；" + (descriptions[artifact.reason_code] || "报告 / PoC 草稿生成或校验失败，未保留草稿。") + "（原因码：" + (artifact.reason_code || "not_recorded") + "）";
}
