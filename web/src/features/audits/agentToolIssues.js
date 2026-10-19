const safeMessages = {
  source_range_too_large: "每次最多读取 40 行。可按 40 行以内拆分重试；无法补齐时将相关义务保持未决。",
  source_outside_fixed_inventory: "该文件不在本次固定扫描清单中，不能读取。请使用固定提交检索工具返回的文件，或保持相关义务未决。",
  source_range_out_of_bounds: "请求起始行超出固定文件范围。请使用有效的一基行号重试，或保持相关义务未决。",
  fixed_evidence_unavailable: "固定提交证据当前不可用；相关义务应保持未决。",
  query_rejected: "只读工具拒绝了该请求；查看原因码和参数后可调整查询，或保持相关义务未决。",
  tool_budget_exhausted: "只读工具预算已用尽，此请求没有执行；相关义务应保持未决。",
};

export function agentToolIssues(toolCalls) {
  if (!Array.isArray(toolCalls)) return [];
  return toolCalls.filter((call) => call && (call.status === "rejected"
      || call.status === "unavailable" || call.status === "not_executed"))
    .map((call) => {
      const result = call.result && typeof call.result === "object" ? call.result : {};
      const tool = typeof call.tool === "string" ? call.tool : "未知工具";
      const recordedLineCount = call.arguments && typeof call.arguments === "object"
        ? call.arguments.line_count : undefined;
      const recordedLimitViolation = tool === "read_fixed_source_range"
        && Number.isInteger(recordedLineCount) && recordedLineCount > 40;
      const code = result.error_code === "query_rejected" && recordedLimitViolation
        ? "source_range_too_large"
        : (typeof result.error_code === "string" ? result.error_code : "");
      return {
        tool,
        status: typeof call.status === "string" ? call.status : "unknown",
        errorCode: code || "unknown",
        message: safeMessages[code] || "工具未能提供证据；相关义务应保持未决。",
      };
    });
}
