import test from "node:test";
import assert from "node:assert/strict";
import { canApproveSourceSubmission, canCreateAgentInvestigation, disclosureReviewed, disclosureSelectionMatches, redactionNotice } from "../src/features/audits/egressDisclosure.js";

test("no recognized secret formats still warns that source may contain secrets", () => {
  const message = redactionNotice({ sensitive_redactions: [], redaction_policy_version: "policy-1" });
  assert.match(message, /未检测到已知凭据格式/);
  assert.match(message, /不代表源码中没有秘密/);
  assert.match(message, /不是完整 DLP/);
  assert.match(message, /跨文件追查可能追加发送的数据范围/);
  assert.match(message, /policy-1/);
});

test("detected secret categories are shown with the same incomplete-DLP warning", () => {
  const message = redactionNotice({
    sensitive_redactions: ["database_uri_password", "azure_sas_signature"],
    redaction_policy_version: "policy-2",
  });
  assert.match(message, /database_uri_password、azure_sas_signature/);
  assert.match(message, /不是完整 DLP/);
  assert.match(message, /policy-2/);
});

test("authorization review requires every actual-context disclosure to be opened", () => {
  assert.equal(disclosureReviewed([], ["initial-context"]), false);
  assert.equal(disclosureReviewed(["metadata"], ["initial-context"]), false);
  assert.equal(disclosureReviewed(["r1"], ["r1", "r2"]), false);
  assert.equal(disclosureReviewed(["r1", "r2", "scope"], ["r1", "r2"]), true);
  assert.equal(disclosureReviewed(["candidate-a"], ["candidate-a", "candidate-b"]), false);
  assert.equal(disclosureReviewed([], []), false);
});

test("preview disclosure must cover exactly the selected candidate or experiment arms", () => {
  assert.equal(disclosureSelectionMatches(["a", "b"], ["b", "a"]), true);
  assert.equal(disclosureSelectionMatches(["a", "b"], ["a"]), false);
  assert.equal(disclosureSelectionMatches(["a"], ["a", "extra"]), false);
  assert.equal(disclosureSelectionMatches(["a", "a"], ["a", "b"]), false);
  assert.equal(disclosureSelectionMatches([], []), false);
});

test("source export consent stays disabled until the eligible preview is expanded", () => {
  const eligible = { agent_execution: { eligible: true } };
  assert.equal(canApproveSourceSubmission({ ready: false, preview: eligible, disclosureOpened: true }), false);
  assert.equal(canApproveSourceSubmission({ ready: true, preview: null, disclosureOpened: true }), false);
  assert.equal(canApproveSourceSubmission({ ready: true, preview: eligible, disclosureOpened: false }), false);
  assert.equal(canApproveSourceSubmission({ ready: true, preview: { agent_execution: { eligible: false } }, disclosureOpened: true }), false);
  assert.equal(canApproveSourceSubmission({ ready: true, preview: eligible, disclosureOpened: true }), true);
});

test("model investigation creation requires the reviewed preview, bound candidate, and explicit consent", () => {
  const eligible = { agent_execution: { eligible: true } };
  const reviewed = { ready: true, jobId: "job-1", candidateId: "candidate-1", preview: eligible, disclosureOpened: true };
  assert.equal(canCreateAgentInvestigation({ ...reviewed, approved: false }), false);
  assert.equal(canCreateAgentInvestigation({ ...reviewed, jobId: undefined, approved: true }), false);
  assert.equal(canCreateAgentInvestigation({ ...reviewed, candidateId: undefined, approved: true }), false);
  assert.equal(canCreateAgentInvestigation({ ...reviewed, disclosureOpened: false, approved: true }), false);
  assert.equal(canCreateAgentInvestigation({ ...reviewed, approved: true }), true);
});
