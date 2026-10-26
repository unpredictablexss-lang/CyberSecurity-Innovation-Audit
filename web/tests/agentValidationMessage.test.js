import test from "node:test";
import assert from "node:assert/strict";
import { artifactFailureMessage, structuredAnswerRejection } from "../src/features/audits/agentValidationMessage.js";

test("policy gate rejection explains why the answer was discarded", () => {
  const message = structuredAnswerRejection("rejected_after_one_repair", "unresolved_authorization_policy_claim");
  assert.match(message, /关闭仍需人工复核的调用方授权策略义务/);
  assert.match(message, /服务端已拒绝并丢弃答复/);
  assert.match(message, /所有义务仍保持未决/);
  assert.match(message, /unresolved_authorization_policy_claim/);
});

test("unknown rejection codes get a safe fallback without implying a vulnerability verdict", () => {
  const message = structuredAnswerRejection("rejected_after_one_repair", "future_unknown_code");
  assert.match(message, /未通过服务端的结构、引用或策略校验/);
  assert.match(message, /当前“未知”结果不构成漏洞判断/);
  assert.match(message, /future_unknown_code/);
});

test("provider output truncation is explicit and retry requires a fresh preview and consent", () => {
  const message = structuredAnswerRejection("provider_incomplete", "max_output_tokens");
  assert.match(message, /达到本次单请求输出 token 上限/);
  assert.match(message, /已丢弃不完整答复/);
  assert.match(message, /所有证据义务仍保持未决/);
  assert.match(message, /重新预览并单独授权/);
  assert.match(message, /不代表候选误报或安全/);
});

test("other incomplete provider responses stay fail-closed and explain retry boundary", () => {
  const message = structuredAnswerRejection("provider_incomplete", "provider_incomplete");
  assert.match(message, /响应未完整结束/);
  assert.match(message, /已丢弃不完整答复/);
  assert.match(message, /重新预览并单独授权/);
});

test("accepted and legacy statuses do not show a rejection alert", () => {
  assert.equal(structuredAnswerRejection("accepted", "invalid_json"), null);
  assert.equal(structuredAnswerRejection(undefined, undefined), null);
});


test("schema and source citation failures have distinct Chinese explanations", () => {
  assert.match(structuredAnswerRejection("rejected_after_repeated_validation_error", "invalid_schema"), /顶层字段/);
  assert.match(structuredAnswerRejection("rejected_after_repeated_validation_error", "invalid_claim_structure"), /obligation_indices/);
  assert.match(structuredAnswerRejection("rejected_after_repeated_validation_error", "invalid_source_line_range"), /连续 8 行/);
});


test("historical skeptic failures are explicit, without inventing missing details", () => {
  const message = structuredAnswerRejection("skeptic_incomplete", "invalid_skeptic_response");
  assert.match(message, /独立复核/);
  assert.match(message, /旧记录没有保存更细/);
});

test("new diagnostics show exact schema path and allowed enum", () => {
  const message = structuredAnswerRejection("skeptic_incomplete", "invalid_skeptic_response", {
    code: "skeptic_invalid_review", issues: [{kind:"enum", path:"$.reviews[2].result", allowed:["unknown"]}]
  });
  assert.match(message, /reviews\[2\].result/);
  assert.match(message, /状态必须使用 unknown/);
});

test("schema errors list missing fields and extra field count", () => {
  const message = structuredAnswerRejection("rejected_after_one_repair", "invalid_schema", {
    issues: [{kind:"object_keys", path:"$", missing:["obligation_reviews"], unexpected_field_count:2}]
  });
  assert.match(message, /缺少 obligation_reviews/);
  assert.match(message, /多余字段 2 个/);
});

test("unknown provider outcome does not claim the output cap was reached", () => {
  const message = structuredAnswerRejection("provider_incomplete", "provider_request_outcome_unknown");
  assert.match(message, /没有取得可确认的完整响应/);
  assert.doesNotMatch(message, /达到本次单请求输出/);
});


test("artifact failure is distinct from accepted primary analysis", () => {
  assert.equal(artifactFailureMessage({status:"completed"}), null);
  assert.match(artifactFailureMessage({status:"rejected", reason_code:"artifact_citation_outside_inventory"}), /主分析与复核已通过/);
  assert.match(artifactFailureMessage({status:"rejected", reason_code:"artifact_citation_outside_inventory"}), /固定源码清单或授权路径/);
});
