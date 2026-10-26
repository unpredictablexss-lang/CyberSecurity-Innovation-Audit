export function caseReportView(report = {}) {
  const operations = Array.isArray(report.operations) ? report.operations : [];
  const metadata = report.operation_summaries || {};
  const included = operations.length;
  const total = Number.isInteger(metadata.total) && metadata.total >= included
    ? metadata.total : included;
  const limit = Number.isInteger(metadata.limit) && metadata.limit > 0 ? metadata.limit : included;
  const truncated = metadata.truncated === true || total > included;
  return {
    candidates: Array.isArray(report.candidates) ? report.candidates : [],
    operations,
    operationScope: { included, total, limit, truncated, omitted: Math.max(0, total - included) },
    agentOperations: operations.filter((item) => item?.kind === "agent_investigation" && item.agent_triage),
    validationOperations: operations.filter((item) => item?.kind === "validation"),
    otherOperations: operations.filter((item) => !["agent_investigation", "validation"].includes(item?.kind)),
    validatedVulnerability: Number.isInteger(report.validated_vulnerability)
      ? report.validated_vulnerability : 0,
  };
}

export function caseReportOperationScopeLabel(scope = {}) {
  const included = Number.isInteger(scope.included) ? scope.included : 0;
  const total = Number.isInteger(scope.total) ? scope.total : included;
  return `当前报告展开 ${included} / ${total} 条`;
}

export function caseReportAgentFeedbackBoundary(reviews = []) {
  return reviews.length
    ? "以下是绑定到该智能调查操作的人工研判反馈；它不等于盲评准确率，也不是漏洞真值。"
    : "该智能调查操作没有登记人工分诊反馈；不能据此推断模型有效或无效。";
}
