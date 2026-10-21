import test from "node:test";
import assert from "node:assert/strict";
import { buildPocValidationPlan } from "../src/features/cases/pocPlanModel.js";

const sha = (char) => char.repeat(64);
const commit = (char) => char.repeat(40);
const row = () => ({
  repository: "openharmony/sample",
  commit: commit("a"),
  report_sha256: sha("b"),
  candidate: {
    id: "candidate-1", file: "src/auth.cpp", line: 41, source_sha256: sha("c"),
    evidence_obligations: [{ kind: "reachability", description: "Trace the product entry." }],
    finding_identity: { source_binding: {
      repository: "openharmony/sample", commit: commit("a"), snapshot_sha256: sha("d"),
      tree_oid: commit("e"), source_blob_oid: commit("f"), source_sha256: sha("c"), file: "src/auth.cpp",
      profile_id: "profile:cpp", detector_id: "detector:cpp", detector_version: "1.2.0",
      rule_id: "rule:auth", rule_version: "1.0.0", byte_start: 100, byte_end: 120,
      status: "bound", verification: "not_performed_by_identity_layer",
    } },
  },
  source_evidence: [{ id: "ev-1", file: "src/auth.cpp", start_line: 40, end_line: 44, note: "Review this guard." }],
});

test("plan binds to exact candidate source and imports obligations only from matching Agent operation", () => {
  const agent = {
    id: "op-agent-1", kind: "agent_investigation", status: "completed",
    agent_triage: {
      binding: { repository: "openharmony/sample", commit: commit("a"), file: "src/auth.cpp", candidate_id: "candidate-1" },
      initial_evidence: { context: { file: "src/auth.cpp", source_sha256: sha("c"), evidence_obligations: [
        { kind: "impact", description: "Identify the sensitive operation." },
      ] } },
    },
  };
  const plan = buildPocValidationPlan(row(), [agent]);
  assert.equal(plan.sourceBinding.sourceSha256, sha("c"));
  assert.equal(plan.sourceBinding.snapshotSha256, sha("d"));
  assert.equal(plan.sourceBinding.treeOid, commit("e"));
  assert.equal(plan.sourceBinding.sourceBlobOid, commit("f"));
  assert.equal(plan.sourceBindingComplete, true);
  assert.equal(plan.findingState, "candidate / unknown");
  assert.equal(plan.executionStatus, "not_executed");
  assert.equal(plan.title, "PoC 计划草案（未执行）");
  assert.deepEqual(plan.matchingAgentOperationIds, ["op-agent-1"]);
  assert.deepEqual(plan.obligations.map((item) => item.kind), ["reachability", "impact"]);
  assert.deepEqual(plan.obligations.map((item) => item.sourceLabel), [
    "静态扫描候选", "绑定到本候选的 Agent 调查",
  ]);
  assert.equal(plan.obligations[0].statusLabel, "待确认");
  assert.equal(plan.obligations[0].kindLabel, "入口与调用链");
  assert.equal(plan.sourceEvidence[0].id, "ev-1");
  assert.equal(plan.executed, false);
  assert.equal(plan.generatedExecutable, false);
});

test("mismatched Agent, file evidence, and validation revision are excluded rather than borrowed", () => {
  const candidate = row();
  candidate.source_evidence.push({ id: "wrong-file", file: "src/other.cpp", start_line: 1, note: "unrelated" });
  candidate.source_evidence.push({ id: "missing-file", start_line: 1, note: "unbound" });
  const mismatchedAgent = {
    id: "op-agent-other", kind: "agent_investigation",
    agent_triage: {
      binding: { repository: "openharmony/sample", commit: commit("d"), file: "src/auth.cpp", candidate_id: "candidate-1" },
      initial_evidence: { context: { evidence_obligations: ["Must not be copied"] } },
    },
  };
  const mismatchedValidation = {
    id: "op-validation-other", kind: "validation", status: "completed",
    validation_evidence: { target_repository: "openharmony/sample", target_commit: commit("d"), harness_id: "unrelated" },
  };
  const plan = buildPocValidationPlan(candidate, [mismatchedAgent, mismatchedValidation]);
  assert.deepEqual(plan.matchingAgentOperationIds, []);
  assert.deepEqual(plan.validationContext, []);
  assert.equal(plan.sourceEvidence.length, 1);
  assert.deepEqual(plan.obligations.map((item) => item.description), ["Trace the product entry."]);
});

test("missing source identity stays unknown and plan contains no executable command or payload", () => {
  const incomplete = { repository: "openharmony/sample", candidate: { id: "candidate-unknown", file: "src/auth.cpp" } };
  const plan = buildPocValidationPlan(incomplete, []);
  assert.equal(plan.sourceBindingComplete, false);
  assert.equal(plan.executionStatus, "not_executed");
  assert.equal(plan.findingState, "candidate / unknown");
  assert.ok(plan.bindingMissing.includes("full commit SHA"));
  assert.ok(plan.bindingMissing.includes("source snapshot SHA-256"));
  assert.ok(plan.bindingMissing.includes("Git tree OID"));
  assert.ok(plan.bindingMissing.includes("source Git blob OID"));
  assert.ok(plan.bindingMissing.includes("scan profile ID"));
  assert.ok(plan.unknowns.some((item) => item.includes("构建目标")));
  assert.ok(plan.unknowns.some((item) => item.includes("测试输入")));
  assert.equal("command" in plan, false);
  assert.equal("payload" in plan, false);
  assert.equal(plan.generatedExecutable, false);
  assert.equal(plan.executed, false);
});

test("same-repository and same-commit Harness appears only as non-candidate context", () => {
  const validation = {
    id: "op-validation-context", kind: "validation", status: "completed_with_limitations",
    validation_evidence: {
      target_repository: "openharmony/sample", target_commit: commit("a"), harness_id: "auth01_descriptor_bypass",
    },
  };
  const plan = buildPocValidationPlan(row(), [validation]);
  assert.deepEqual(plan.validationContext, [{
    id: "op-validation-context", status: "completed_with_limitations",
    statusLabel: "已结束（有未解决限制）",
    harnessId: "auth01_descriptor_bypass", targetRepository: "openharmony/sample",
    targetCommit: commit("a"), candidateBound: false,
  }]);
  assert.ok(plan.unknowns.some((item) => item.includes("尚无绑定到本候选的修复版本")));
  assert.equal(plan.executed, false);
});

test("invalid source hash prevents a complete binding even when other identifiers exist", () => {
  const invalid = row();
  invalid.candidate.source_sha256 = "legacy-missing-hash";
  const plan = buildPocValidationPlan(invalid, []);
  assert.equal(plan.sourceBindingComplete, false);
  assert.ok(plan.bindingMissing.includes("candidate source SHA-256"));
  assert.ok(plan.bindingMissing.includes("candidate/source-binding SHA-256 mismatch"));
});


test("raw evidence and operation statuses are rendered as cautious Chinese labels", () => {
  const candidate = row();
  candidate.candidate.evidence_obligations = [
    { kind: "impact", description: "Review the impact.", status: "evidence_found" },
    { kind: "reachability", description: "Check the entry.", status: "unknown" },
  ];
  const plan = buildPocValidationPlan(candidate, []);
  assert.deepEqual(plan.obligations.map((item) => item.statusLabel), [
    "已找到线索（尚不代表义务满足）", "待确认",
  ]);
  assert.deepEqual(plan.obligations.map((item) => item.sourceLabel), [
    "静态扫描候选", "静态扫描候选",
  ]);
  assert.equal(plan.sourceBinding.identityStatusLabel, "来源字段已记录");
});
