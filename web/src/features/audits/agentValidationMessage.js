const rejectionDescriptions = {
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
