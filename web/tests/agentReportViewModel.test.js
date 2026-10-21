import test from "node:test";
import assert from "node:assert/strict";
import {
  buildAgentOperationArtifactView,
  buildAgentReportView,
} from "../src/features/cases/agentReportViewModel.js";

test("bound Agent vulnerability report fields remain readable and source citations are not embellished", () => {
  const view = buildAgentReportView({
    vulnerability_report: {
      title: "Possible authorization gap",
      summary: "A source-level candidate needs review.",
      root_cause: "The check may be missing on one path.",
      impact: "Potentially affects a privileged operation.",
      preconditions: ["Caller reaches the method."],
      attack_path: ["Application entry", "Candidate method"],
      remediation: "Review a central authorization check.",
      citations: [
        { evidence_id: "ev-1", quote: "if (isAllowed)" },
        { evidence_id: "ev-2", file: "src/auth.cpp", line_start: 31, line_end: 33, quote: "callSensitive();" },
      ],
    },
  });
  const report = view.vulnerabilityReport;
  assert.ok(report);
  assert.equal(report.title, "Possible authorization gap");
  assert.equal(report.rootCause, "The check may be missing on one path.");
  assert.deepEqual(report.preconditions, ["Caller reaches the method."]);
  assert.deepEqual(report.attackPath, ["Application entry", "Candidate method"]);
  assert.equal(report.citations[0].location, "");
  assert.equal(report.citations[0].evidenceId, "ev-1");
  assert.equal(report.citations[1].location, "src/auth.cpp:31–33");
  assert.equal(report.citations[1].quote, "callSensitive();");
  assert.match(report.boundary, /candidate \/ unknown/);
});

test("PoC draft is always identified as unexecuted, unverified, and candidate-only", () => {
  const code = "int main() { return 0; }\n";
  const view = buildAgentReportView({
    poc_draft: {
      status: "draft_unexecuted",
      title: "Review-only draft",
      language: "C++",
      code,
      prerequisites: ["Use an isolated disposable build."],
      run_steps: ["Build in the reviewed test environment."],
      expected_observation: "Compare the recorded result with the approved expectation.",
      negative_control: "Run a safe control input.",
      citations: [{ file: "src/auth.cpp", line_start: 8 }],
    },
  });
  const draft = view.pocDraft;
  assert.ok(draft);
  assert.equal(draft.code, code);
  assert.equal(draft.statusLabel, "待人工审查的草案");
  assert.deepEqual(draft.prerequisites, ["Use an isolated disposable build."]);
  assert.deepEqual(draft.runSteps, ["Build in the reviewed test environment."]);
  assert.equal(draft.citations[0].location, "src/auth.cpp:8");
  assert.match(draft.boundary, /AI 草案 · 未执行 · 未验证 · candidate \/ unknown/);
});

test("insufficient evidence remains explicit and malformed states never imply execution", () => {
  const insufficient = buildAgentReportView({
    poc_draft: { status: "insufficient_evidence", expected_observation: "Not established." },
  }).pocDraft;
  assert.equal(insufficient.statusLabel, "证据不足");
  assert.match(insufficient.boundary, /未执行 · 未验证 · candidate \/ unknown/);

  const unknownStatus = buildAgentReportView({
    poc_draft: { status: "unexpected_status", code: "untrusted model text" },
  }).pocDraft;
  assert.equal(unknownStatus.statusLabel, "状态待确认");
  assert.match(unknownStatus.boundary, /未执行 · 未验证/);
  assert.equal(unknownStatus.code, "untrusted model text");
});

test("absent and empty optional Agent reports stay hidden", () => {
  assert.deepEqual(buildAgentReportView({}), {
    vulnerabilityReport: null, pocDraft: null, artifactGeneration: null,
  });
  assert.deepEqual(buildAgentReportView({
    vulnerability_report: {},
    poc_draft: { title: "  ", code: "  ", citations: [] },
  }), { vulnerabilityReport: null, pocDraft: null, artifactGeneration: null });
});

test("non-string narrative/list values are not coerced into fabricated content", () => {
  const view = buildAgentReportView({
    vulnerability_report: { summary: { model: "object" }, preconditions: ["Valid", 7] },
    poc_draft: { status: "draft_unexecuted", run_steps: [null, "One step"] },
  });
  assert.equal(view.vulnerabilityReport.summary, "");
  assert.deepEqual(view.vulnerabilityReport.preconditions, ["Valid"]);
  assert.deepEqual(view.pocDraft.runSteps, ["One step"]);
});

test("completed artifact stage reports draft states and its own model-call count", () => {
  const view = buildAgentReportView({
    vulnerability_report: { status: "draft_unverified", title: "Candidate report" },
    poc_draft: { status: "draft_unexecuted", title: "Review draft" },
    artifact_generation: { status: "completed", calls_used: 1, maximum_model_calls: 1 },
    vulnerability_state: "candidate",
  });
  assert.deepEqual(view.artifactGeneration, {
    status: "completed",
    statusLabel: "阶段已完成",
    reportStatusLabel: "已生成（未验证）",
    pocStatusLabel: "已生成（草案未执行）",
    callsUsed: 1,
    maximumModelCalls: 1,
  });
  assert.match(view.pocDraft.boundary, /未执行/);
  assert.equal(view.artifactGeneration.statusLabel, "阶段已完成");
  assert.notEqual(view.artifactGeneration.statusLabel, "扫描已完成");
});

test("completed artifact stage distinguishes an evidence-insufficient report and PoC", () => {
  const view = buildAgentReportView({
    vulnerability_report: { status: "insufficient_evidence", summary: "Need review." },
    poc_draft: { status: "insufficient_evidence", expected_observation: "Not established." },
    artifact_generation: { status: "completed", calls_used: 1, maximum_model_calls: 1 },
  });
  assert.equal(view.artifactGeneration.reportStatusLabel, "证据不足");
  assert.equal(view.artifactGeneration.pocStatusLabel, "证据不足");
});

test("authorization and not-run stage states take precedence over fallback artifact statuses", () => {
  const fallback = {
    vulnerability_report: { status: "insufficient_evidence", summary: "Fallback." },
    poc_draft: { status: "insufficient_evidence", expected_observation: "Fallback." },
  };
  const unauthorized = buildAgentReportView({
    ...fallback,
    artifact_generation: { status: "not_authorized", calls_used: 0, maximum_model_calls: 1 },
  }).artifactGeneration;
  assert.equal(unauthorized.statusLabel, "未授权");
  assert.equal(unauthorized.reportStatusLabel, "未授权");
  assert.equal(unauthorized.pocStatusLabel, "未授权");
  assert.equal(unauthorized.callsUsed, 0);

  const notRun = buildAgentReportView({
    ...fallback,
    artifact_generation: {
      status: "not_run_primary_answer_unavailable", calls_used: 0, maximum_model_calls: 1,
    },
  }).artifactGeneration;
  assert.match(notRun.statusLabel, /^未运行/);
  assert.match(notRun.reportStatusLabel, /^未运行/);
  assert.match(notRun.pocStatusLabel, /^未运行/);

  const singleShot = buildAgentReportView({
    artifact_generation: { status: "not_applicable_single_shot", calls_used: 0, maximum_model_calls: 0 },
  }).artifactGeneration;
  assert.match(singleShot.statusLabel, /单次模式不适用/);
});

test("failed, interrupted, or rejected generation does not become evidence insufficiency", () => {
  const fallback = {
    vulnerability_report: { status: "insufficient_evidence", summary: "Fallback." },
    poc_draft: { status: "insufficient_evidence", expected_observation: "Fallback." },
  };
  const incomplete = buildAgentReportView({
    ...fallback,
    artifact_generation: { status: "incomplete", calls_used: 1, maximum_model_calls: 1 },
  }).artifactGeneration;
  assert.match(incomplete.statusLabel, /失败 \/ 中断/);
  assert.equal(incomplete.reportStatusLabel, incomplete.statusLabel);
  assert.equal(incomplete.pocStatusLabel, incomplete.statusLabel);

  const rejected = buildAgentReportView({
    ...fallback,
    artifact_generation: { status: "rejected", calls_used: 1, maximum_model_calls: 1 },
  }).artifactGeneration;
  assert.match(rejected.statusLabel, /失败/);
  assert.notEqual(rejected.reportStatusLabel, "证据不足");

  const interrupted = buildAgentReportView({
    artifact_generation: { status: "interrupted", calls_used: 0 },
  }).artifactGeneration;
  assert.equal(interrupted.statusLabel, "已中断");
});

test("unknown stage states and invalid call counters stay unknown instead of being coerced", () => {
  const view = buildAgentReportView({
    vulnerability_report: { status: "draft_unverified", title: "Candidate." },
    poc_draft: { status: "draft_unexecuted", title: "Draft." },
    artifact_generation: {
      status: "future_status", calls_used: "1", maximum_model_calls: -2,
    },
  }).artifactGeneration;
  assert.equal(view.statusLabel, "未知 / 未记录");
  assert.equal(view.reportStatusLabel, "未知 / 未记录");
  assert.equal(view.pocStatusLabel, "未知 / 未记录");
  assert.equal(view.callsUsed, null);
  assert.equal(view.maximumModelCalls, null);
});

test("real Agent operation result path exposes bound report, repair suggestion, and PoC boundary", () => {
  const view = buildAgentOperationArtifactView({
    vulnerability_state: "candidate",
    artifact_generation: { status: "completed", calls_used: 1, maximum_model_calls: 1 },
    agent_assessment: {
      vulnerability_report: {
        status: "draft_unverified",
        title: "Candidate report",
        remediation: "Review and add a permission check before the sensitive call.",
        citations: [{ evidence_id: "ev-1", file: "src/auth.cpp", line_start: 42 }],
      },
      poc_draft: {
        status: "draft_unexecuted",
        title: "Human-review-only PoC draft",
        code: "// displayed as text only",
      },
    },
  });
  assert.equal(view.artifactGeneration.statusLabel, "阶段已完成");
  assert.equal(view.vulnerabilityReport.remediation,
    "Review and add a permission check before the sensitive call.");
  assert.equal(view.vulnerabilityReport.citations[0].location, "src/auth.cpp:42");
  assert.match(view.vulnerabilityReport.boundary, /candidate \/ unknown/);
  assert.equal(view.pocDraft.statusLabel, "待人工审查的草案");
  assert.match(view.pocDraft.boundary, /AI 草案 · 未执行 · 未验证 · candidate \/ unknown/);
  assert.equal(view.pocDraft.code, "// displayed as text only");
});
