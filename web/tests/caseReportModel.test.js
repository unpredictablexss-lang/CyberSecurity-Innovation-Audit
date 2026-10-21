import test from "node:test";
import assert from "node:assert/strict";
import { caseReportAgentFeedbackBoundary, caseReportOperationScopeLabel, caseReportView } from "../src/features/cases/reportModel.js";

test("case report presents operation truncation as an explicit omitted count", () => {
  const view = caseReportView({
    operations: Array.from({ length: 20 }, (_, index) => ({ id: String(index), kind: "validation" })),
    operation_summaries: { total: 25, included: 20, truncated: true, limit: 20 },
  });
  assert.deepEqual(view.operationScope, {
    included: 20, total: 25, limit: 20, truncated: true, omitted: 5,
  });
  assert.equal(caseReportOperationScopeLabel(view.operationScope), "当前报告展开 20 / 25 条");
  assert.equal(view.validationOperations.length, 20);
});

test("case report safely defaults legacy summaries without claiming hidden rows", () => {
  const view = caseReportView({ operations: [{ kind: "agent_investigation", agent_triage: {} }] });
  assert.deepEqual(view.operationScope, {
    included: 1, total: 1, limit: 1, truncated: false, omitted: 0,
  });
});

test("case report keeps Agent triage and fixed validation separate from human confirmation", () => {
  const view = caseReportView({
    validated_vulnerability: 0,
    operations: [
      { kind: "agent_investigation", agent_triage: {} },
      { kind: "validation", validation_evidence: { harness_id: "auth01_descriptor_bypass" } },
    ],
  });
  assert.equal(view.agentOperations.length, 1);
  assert.equal(view.validationOperations.length, 1);
  assert.equal(view.validatedVulnerability, 0);
  assert.match(caseReportAgentFeedbackBoundary([{ usefulness: "useful" }]), /不等于盲评准确率/);
  assert.match(caseReportAgentFeedbackBoundary([]), /不能据此推断模型有效或无效/);
});
