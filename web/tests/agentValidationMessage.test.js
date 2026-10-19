import test from "node:test";
import assert from "node:assert/strict";
import { structuredAnswerRejection } from "../src/features/audits/agentValidationMessage.js";

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
  assert.match(message, /达到本次输出 token 上限/);
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
