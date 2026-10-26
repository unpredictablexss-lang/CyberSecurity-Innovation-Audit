import test from "node:test";
import assert from "node:assert/strict";
import { agentConfidenceLabel, agentScopeLabel, agentVerdictLabel, agentVerdictReasonLabel, analysisStatusLabel, coverageStatusLabel, coverageSummaryLabel, groupingBasisLabel, groupingSymbolLabel, obligationDescriptionLabel, obligationKindLabel, obligationStatusLabel, productStatusLabel, reportLimitationLabel, riskReasonLabel, riskReasonsLabel, scanStageLabel, taskReportStatusLabel, taskTriageStatusLabel, triageStateLabel } from "../src/features/workbench/riskLabels.js";

test("Agent verdict labels separate source evidence from product confirmation", () => {
  assert.equal(agentVerdictLabel("confirmed"), "源码证据门通过（产品状态仍未知）");
  assert.equal(agentVerdictLabel("false_positive"), "源码证据支持误报解释（仍需人工复核）");
  assert.equal(agentConfidenceLabel("high"), "高（模型自评）");
  assert.equal(agentScopeLabel("fixed_source_code"), "固定提交源码");
  assert.equal(productStatusLabel("candidate"), "待复核候选");
  assert.match(
    agentVerdictReasonLabel("All source-review obligations have cited support and no unsupported claims remain."),
    /产品状态仍未知/,
  );
});

test("coverage status enums are localized and incomplete states stay explicit", () => {
  assert.equal(analysisStatusLabel("analyzed"), "静态检查完成");
  assert.equal(analysisStatusLabel("partial"), "部分检查");
  assert.equal(analysisStatusLabel("not_analyzed"), "未检查");
  assert.equal(analysisStatusLabel("unknown"), "未知（待核实）");
  assert.equal(coverageStatusLabel("blocked"), "受阻");
  assert.equal(coverageStatusLabel("completed_with_limitations"), "完成但存在覆盖限制");
  assert.equal(coverageStatusLabel("new_status"), "未知（待核实）");
});

test("coverage summary uses localized counts and preserves missing values as unknown", () => {
  assert.equal(
    coverageSummaryLabel({ complete: 94, partial: 29 }, 0),
    "解析覆盖：完整 94 个、部分 29 个、失败 未知、未运行 未知；未被检测器认领 0 个。",
  );
  assert.equal(
    coverageSummaryLabel(null, null),
    "解析覆盖：完整 未知、部分 未知、失败 未知、未运行 未知；未被检测器认领 未知。",
  );
});

test("cluster grouping metadata is readable without implying root-cause identity", () => {
  assert.equal(
    groupingBasisLabel("same detector/version, rule, file, symbol, and source hash"),
    "仓库快照、Detector 版本、规则、文件、符号和源码哈希均一致",
  );
  assert.equal(groupingBasisLabel("future grouping basis"), "按报告记录的字段分组");
  assert.equal(groupingSymbolLabel("handler"), "handler");
  assert.equal(groupingSymbolLabel(""), "未识别符号");
});

test("workflow status codes are shown in Chinese across overview and task detail", () => {
  assert.equal(triageStateLabel("not_triaged"), "未研判");
  assert.equal(triageStateLabel("waiting_for_authorization"), "等待本次任务授权");
  assert.equal(scanStageLabel("agent_review_queued"), "扫描已完成；候选等待你决定是否授权研判");
});

test("evidence obligations use readable Chinese labels without changing unknown into a verdict", () => {
  assert.equal(obligationKindLabel("callee_binding"), "调用目标与实现");
  assert.equal(obligationStatusLabel("unknown"), "未知（待核实）");
  assert.match(obligationStatusLabel("evidence_found"), /仍需人工复核/);
  assert.equal(
    obligationDescriptionLabel("No log exposure or reader reachability is established by this call alone."),
    "仅凭此调用无法证明存在日志泄露或可触达的读取方。",
  );
  assert.equal(obligationDescriptionLabel("new rule text"), "new rule text");
  assert.equal(obligationKindLabel("custom_check"), "核查项：custom_check");
  assert.equal(obligationStatusLabel("unexpected"), "状态未知");
});

test("risk explanations preserve evidence limits in user-facing language", () => {
  assert.equal(riskReasonLabel("candidate analysis is partial or unknown"), "候选分析不完整或状态未知。");
  assert.match(riskReasonLabel("a human marked this item as refuted or low-priority; this is not a safety verdict"), /不代表已证明安全/);
  assert.equal(riskReasonLabel("unrecognized backend detail"), "需要进一步核对本项证据。");
  assert.equal(
    riskReasonsLabel(["candidate analysis is partial or unknown", "no complete quoted static-human evidence review is recorded"]),
    "候选分析不完整或状态未知；尚未完成带源码引用的静态人工复核。",
  );
  assert.equal(riskReasonsLabel([]), "需要进一步核对本项证据。");
});

test("report caveats are readable in Chinese while unknown messages are preserved", () => {
  assert.equal(reportLimitationLabel("Zero diagnostics does NOT mean the component is free of vulnerabilities."),
    "零条候选不代表组件不存在漏洞。");
  assert.match(reportLimitationLabel("Diagnostics are candidates/evidence only, not proof of security impact."), /待复核候选/);
  assert.equal(reportLimitationLabel("new detector limitation"), "new detector limitation");
  assert.equal(reportLimitationLabel(""), "报告未提供限制说明。");
});

test("task detail shows loading states instead of false waiting or unknown labels", () => {
  const job = { status: "completed", report_sha256: "a".repeat(64) };
  assert.equal(taskReportStatusLabel(null, job), "正在读取报告状态");
  assert.equal(taskTriageStatusLabel(null, job), "正在读取研判状态");
  assert.equal(taskReportStatusLabel({ report_status: "ready" }, job), "已生成");
  assert.equal(taskTriageStatusLabel({ triage_status: "waiting_for_authorization" }, job),
    "等待本次任务授权");
  assert.equal(taskReportStatusLabel(null, { status: "running", report_sha256: null }), "等待报告");
  assert.equal(taskTriageStatusLabel(null, { status: "running", report_sha256: null }),
    "等待静态扫描报告");
});
