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

export function structuredAnswerRejection(status, errorCode) {
  if (status === "provider_incomplete") {
    if (errorCode === "max_output_tokens") {
      return "Provider 响应达到本次单请求输出 token 上限；服务端已丢弃不完整答复，所有证据义务仍保持未决。若要调整单次上限后重试，请重新预览并单独授权；本次结果不代表候选误报或安全。";
    }
    return "Provider 响应未完整结束；服务端已丢弃不完整答复，所有证据义务仍保持未决。核对任务状态后如需重试，请重新预览并单独授权；本次结果不代表候选误报或安全。";
  }
  if (typeof status !== "string" || !status.startsWith("rejected_")) return null;
  const code = typeof errorCode === "string" ? errorCode : "";
  const description = rejectionDescriptions[code]
    || "最终结构化答复未通过服务端的结构、引用或策略校验。系统已丢弃模型主张，并将所有义务保持未决；当前“未知”结果不构成漏洞判断。";
  return description + (code ? "（原因码：" + code + "）" : "");
}
