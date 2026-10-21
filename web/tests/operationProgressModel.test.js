import test from "node:test";
import assert from "node:assert/strict";
import {
  buildIntelligentReviewView, buildMatrixCandidatePairs, buildRecentWindowCandidatePairs,
  buildJointLinkedAgentChildrenView, buildJointEgressSummary, JOINT_CANDIDATE_CREATE_PATH, JOINT_CANDIDATE_PREVIEW_PATH,
  RECENT_JOINT_CANDIDATE_CREATE_PATH, RECENT_JOINT_CANDIDATE_PREVIEW_PATH,
  jointCandidateCreatePayload, jointCandidatePreviewPayload,
} from "../src/features/audits/operationProgressModel.js";

const from = "a".repeat(40), to = "b".repeat(40);
const sha = "c".repeat(64);

test("phase progress separates statuses and only exposes child links bound to the endpoint commit", () => {
  const row = buildIntelligentReviewView({
    commit: from, agent_status: "partially_completed", candidate_count: 4,
    triage_state_reason: "Only part completed.",
    r1_progress: { state: "partially_completed", status_counts: { completed: 1, failed: 1, interrupted: 1 },
      failure_reasons: [{ operation_id: "op-fail", candidate_id: "cid-fail", status: "failed", reason: "quota" }] },
    r2_progress: { state: "not_triaged" },
    r1_operations: [
      { id: "op-ok", status: "completed", commit: from, candidate_id: "cid-ok", result_sha256: sha, report_sha256: sha },
      { id: "op-mismatch", status: "completed", commit: to, candidate_id: "cid-bad", result_sha256: "not-a-hash" },
    ],
  });
  assert.equal(row.stateLabel, "部分完成，仍有候选未研判或调用失败");
  assert.equal(row.r1.counts.completed, 1);
  assert.equal(row.r1.counts.failed, 1);
  assert.equal(row.r1.counts.interrupted, 1);
  assert.equal(row.r1.reasons[0].reason, "quota");
  assert.equal(row.r1.operations[0].bindingValid, true);
  assert.equal(row.r1.operations[0].resultSha256, sha);
  assert.equal(row.r1.operations[1].bindingValid, false);
  assert.match(row.r1.operations[1].bindingIssue, /Commit/);
  assert.equal(row.r1.operations[1].resultSha256, null);
  assert.equal(row.r1.summariesReturned, true);
});

test("limited completion remains distinct in labels, counts, tone, and result bindings", () => {
  const row = buildIntelligentReviewView({
    commit: from, agent_status: "completed_with_limitations",
    r1_progress: { state: "completed_with_limitations", status_counts: { completed: 1, completed_with_limitations: 1 } },
    r1_operations: [
      { id: "op-limited", status: "completed_with_limitations", commit: from, candidate_id: "cid-limited",
        result_sha256: sha, report_sha256: sha },
    ],
  });
  assert.equal(row.stateLabel, "授权范围内研判已返回（存在限制）");
  assert.equal(row.stateTone, "warning");
  assert.equal(row.r1.stateLabel, "已完成（存在限制）");
  assert.equal(row.r1.counts.completed, 1);
  assert.equal(row.r1.counts.completed_with_limitations, 1);
  assert.equal(row.r1.operations[0].statusLabel, "已完成（存在限制）");
  assert.equal(row.r1.operations[0].bindingValid, true);
  const unbound = buildIntelligentReviewView({
    commit: from, r1_operations: [
      { id: "op-limited-unbound", status: "completed_with_limitations", commit: from },
    ],
  });
  assert.equal(unbound.r1.operations[0].bindingValid, false);
});

test("missing child summary arrays are distinguished from an explicitly empty operation list", () => {
  const missing = buildIntelligentReviewView({ commit: from, agent_status: "completed", r1_progress: { operation_count: 1 } });
  const empty = buildIntelligentReviewView({ commit: from, agent_status: "not_triaged", r1_operations: [] });
  assert.equal(missing.r1.summariesReturned, false);
  assert.equal(empty.r1.summariesReturned, true);
  assert.equal(missing.r1.operationCount, 1);
});

test("completed child links require valid result and source report hashes", () => {
  const row = buildIntelligentReviewView({ commit: from, r1_operations: [
    { id: "op-missing-report", status: "completed", commit: from, result_sha256: sha },
    { id: "op-queued", status: "queued", commit: from },
  ] });
  assert.equal(row.r1.operations[0].bindingValid, false);
  assert.match(row.r1.operations[0].bindingIssue, /Report SHA-256/);
  assert.equal(row.r1.operations[1].bindingValid, true);
});

test("endpoint states distinguish full success, all-failed, revoked and not-triaged", () => {
  const make = (agent_status) => buildIntelligentReviewView({ commit: from, agent_status });
  assert.equal(make("completed").stateLabel, "授权范围内研判已完成");
  assert.equal(make("failed").stateLabel, "全部已选 Agent 调用均失败");
  assert.equal(make("revoked").stateLabel, "外发授权已撤销");
  assert.equal(make("not_triaged").stateLabel, "尚未研判");
  assert.equal(make("static_only").isStatic, true);
});

test("matrix pair model only enables a uniquely matched one-to-one fixed candidate pair", () => {
  const operation = { id: "matrix-1", result: { comparisons: [
    { from, to, candidate_comparison: [
      { status: "persistent_candidate", detector_id: "det", rule_id: "rule", file: "src/a.cpp",
        match_basis: "detector_rule_path_symbol", before: [{ id: "candidate-a", source_sha256: sha }],
        after: [{ id: "candidate-b", source_sha256: sha }] },
      { status: "unknown", detector_id: "det", rule_id: "ambiguous", file: "src/b.cpp",
        before: [{ id: "candidate-c" }, { id: "candidate-d" }], after: [{ id: "candidate-e" }] },
    ] },
  ] } };
  const pairs = buildMatrixCandidatePairs(operation);
  assert.equal(pairs.length, 2);
  assert.equal(pairs[0].eligibleForPreview, true);
  assert.equal(pairs[0].fromCandidate.id, "candidate-a");
  assert.equal(pairs[1].eligibleForPreview, false);
  assert.equal(pairs[1].fromCandidate, null);
});

test("recent-window pair selectors bind only the fixed between-window endpoints", () => {
  const operation = { id: "recent-1", kind: "recent_window_comparison", result: {
    between_window_endpoints: { from, to, candidate_comparison: [
      { status: "persistent_candidate", detector_id: "det", rule_id: "rule", file: "src/a.cpp",
        before: [{ id: "candidate-a" }], after: [{ id: "candidate-b" }] },
      { status: "new_candidate", detector_id: "det", rule_id: "new", file: "src/b.cpp",
        before: [], after: [{ id: "candidate-c" }] },
    ] },
  } };
  const pairs = buildRecentWindowCandidatePairs(operation);
  assert.equal(pairs.length, 2);
  assert.equal(pairs[0].eligibleForPreview, true);
  assert.equal(pairs[1].eligibleForPreview, false);
  assert.deepEqual(jointCandidatePreviewPayload("recent-1", pairs[0], "recent_window_comparison"), {
    recent_window_operation_id: "recent-1", from_commit: from, from_candidate_id: "candidate-a",
    to_commit: to, to_candidate_id: "candidate-b",
  });
  assert.equal(RECENT_JOINT_CANDIDATE_PREVIEW_PATH, "/operations/joint-candidate-comparisons/preview");
  assert.equal(RECENT_JOINT_CANDIDATE_CREATE_PATH, "/operations/joint-candidate-comparisons");
});

test("preview request contains only pair selectors; no caller-chosen source or Provider data", () => {
  const pair = { fromCommit: from, toCommit: to, fromCandidate: { id: "candidate-a" }, toCandidate: { id: "candidate-b" },
    repository: "forged", provider: "forged", source_sha256: "forged" };
  assert.deepEqual(jointCandidatePreviewPayload("matrix-1", pair), {
    matrix_operation_id: "matrix-1", from_commit: from, from_candidate_id: "candidate-a",
    to_commit: to, to_candidate_id: "candidate-b",
  });
  assert.throws(() => jointCandidatePreviewPayload("matrix-1", { ...pair, toCommit: from }), /不同/);
  assert.equal(JOINT_CANDIDATE_PREVIEW_PATH, "/operations/version-matrix-candidate-comparisons/preview");
});

test("create requires the preview consent nonce, expiry, digest and sends explicit approval", () => {
  const pair = { fromCommit: from, toCommit: to, fromCandidate: { id: "candidate-a" }, toCandidate: { id: "candidate-b" } };
  assert.deepEqual(jointCandidateCreatePayload("matrix-1", pair, { consent_nonce: "nonce-1", consent_sha256: sha, expires_at: "2026-10-21T00:00:00Z" }), {
    matrix_operation_id: "matrix-1", from_commit: from, from_candidate_id: "candidate-a",
    to_commit: to, to_candidate_id: "candidate-b", approved: true,
    consent_nonce: "nonce-1", expected_consent_sha256: sha, expires_at: "2026-10-21T00:00:00Z",
  });
  assert.equal(JOINT_CANDIDATE_CREATE_PATH, "/operations/version-matrix-candidate-comparisons");
  assert.throws(() => jointCandidateCreatePayload("matrix-1", pair, { consent_nonce: "nonce-1", consent_sha256: sha }), /有效期/);
});

test("joint preview renders linked Agent summaries only when supplied and bound fields exist", () => {
  const missing = buildJointLinkedAgentChildrenView({ linked_agent_result_count: 2 });
  assert.equal(missing.resultCount, 2);
  assert.equal(missing.from.provided, false);
  const present = buildJointLinkedAgentChildrenView({ linked_agent_result_count: 1, linked_agent_children: {
    from: [{ operation_id: "agent-1", status: "completed", result_sha256: sha }],
    to: [{ operation_id: "agent-queued", status: "queued" }],
  } });
  assert.equal(present.from.items[0].linkValid, true);
  assert.equal(present.from.items[0].resultSha256, sha);
  assert.equal(present.to.items[0].linkValid, true);
  const invalid = buildJointLinkedAgentChildrenView({ linked_agent_children: {
    from: [{ operation_id: "agent-unbound", status: "completed", result_sha256: "bad" }], to: [],
  } });
  assert.equal(invalid.from.items[0].linkValid, false);
});

test("joint consent summary distinguishes missing evidence lists from explicit empty lists", () => {
  const missing = buildJointEgressSummary({ source_evidence_count: 3 });
  assert.equal(missing.evidenceProvided, false);
  assert.equal(missing.evidenceCount, null);
  assert.equal(missing.fileCount, null);
  assert.equal(missing.linkedReviewProvided, false);
  assert.equal(missing.linkedReviewCount, null);
  const present = buildJointEgressSummary({
    source_evidence_count: 2,
    evidence_preview: [
      { file: "src/a.cpp", side: "from" },
      { file: "src/a.cpp", side: "to" },
      { file: "src/b.cpp", side: "to" },
    ],
    linked_review_manifest: { from: [{ summary_transmitted: "one" }], to: [] },
  });
  assert.equal(present.evidenceProvided, true);
  assert.equal(present.evidenceCount, 3);
  assert.equal(present.sourceEvidenceCount, 2);
  assert.equal(present.fileCount, 2);
  assert.equal(present.linkedReviewProvided, true);
  assert.equal(present.linkedReviewCount, 1);
  assert.equal(present.linkedReviewToCount, 0);
});