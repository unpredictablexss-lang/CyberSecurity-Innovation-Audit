import test from "node:test";
import assert from "node:assert/strict";
import {
  budgetEnforcementLabel, budgetStateLabel, investigationStopReasonLabel,
  modelReviewStatusLabel, quickAssessmentLabel, quickScreenPresentation, quickScreenStateLabel,
} from "../src/features/audits/quickScreenPresentation.js";

test("quick-screen enums and tool hints are presented in Chinese", () => {
  const view = quickScreenPresentation({
    quick_assessment: "possible_refutation",
    review_status: "model_unverified",
    rationale: "模型发现了可能的边界检查，但仍需要核验。",
    missing_obligations: ["确认输入长度来源"],
    next_tool_hints: ["find_callers", "inspect_guard"],
    uncertainties: ["调用路径尚未完整核实"],
    budget_state: "active",
  }, "completed");
  assert.equal(view.assessment, "发现待复核的反证线索");
  assert.equal(view.reviewStatus, "模型意见待人工核验");
  assert.equal(view.requestState, "已完成");
  assert.equal(view.nextSteps, "查找调用位置、检查权限与边界校验");
  assert.equal(view.budgetState, "进行中");
  assert.equal(view.hasEnglishOriginal, false);
});

test("mixed English quick-screen explanation is folded and kept in history", () => {
  const view = quickScreenPresentation({
    quick_assessment: "investigate",
    rationale: "该调用 may return null when the guard is missing.",
    missing_obligations: [],
    uncertainties: [],
  }, "completed");
  assert.equal(view.hasEnglishOriginal, true);
  assert.match(view.rationale, /详细说明以英文返回/);
});

test("historical English model prose gets a Chinese-first notice and remains marked for technical review", () => {
  const view = quickScreenPresentation({
    quick_assessment: "investigate",
    review_status: "model_unverified",
    rationale: "The size is bounded before resize; failure handling remains unverified.",
    missing_obligations: ["Bind the destination object to its storage width."],
    next_tool_hints: ["inspect_guard"],
    uncertainties: ["Reachability is unknown."],
  }, "completed");
  assert.match(view.rationale, /详细说明以英文返回/);
  assert.match(view.missingEvidence, /1 项/);
  assert.match(view.uncertainties, /1 项/);
  assert.equal(view.hasEnglishOriginal, true);
});

test("unknown codes fail closed to readable Chinese labels", () => {
  assert.equal(quickAssessmentLabel("unexpected"), "建议待核对");
  assert.equal(quickScreenStateLabel("unexpected"), "状态未知");
  assert.equal(modelReviewStatusLabel("unexpected"), "模型意见待核验");
  assert.equal(budgetStateLabel("active"), "进行中");
});

test("L3 stop and budget states use Chinese display labels", () => {
  assert.equal(investigationStopReasonLabel("completed_with_limitations"), "调查已结束，部分内容受限");
  assert.equal(investigationStopReasonLabel("provider_internal_code"), "因技术原因停止，详情见原始记录");
  assert.equal(budgetEnforcementLabel("advisory_only"), "仅记录实际用量");
});
