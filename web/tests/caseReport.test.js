import test from "node:test";
import assert from "node:assert/strict";
import {
  caseAgentEvidencePresentation,
  casePocPlanPresentation,
  caseRemediationDraftPresentation,
} from "../src/features/workbench/caseReport.js";

const anchor = {
  verified: true,
  anchor_id: "src-fixed-candidate",
  commit: "a".repeat(40),
  source_sha256: "b".repeat(64),
};

test("case UI suppresses AI narrative when citations or fixed source binding are missing", () => {
  const triage = {
    summary: "unbound summary must stay hidden",
    supported_claims: [{ claim: "unbound claim" }],
    unknowns: ["unbound unknown"],
    model_suggestions: [{ text: "unbound advice", source_anchor: anchor }],
    citation_review: { state: "unknown", citations: [], reason: "source mismatch" },
  };
  const noCitation = caseAgentEvidencePresentation({
    ...triage,
    citation_review: { state: "unverified_model_advice", citations: [] },
  }, anchor);
  assert.equal(noCitation.available, false);
  assert.equal(noCitation.summary, "");
  assert.deepEqual(noCitation.supportedClaims, []);
  assert.deepEqual(noCitation.modelSuggestions, []);
  assert.equal(caseAgentEvidencePresentation(triage, { ...anchor, verified: false }).available, false);
});

test("case UI shows source-bound AI suggestions only as unverified and hides cross-candidate references", () => {
  const otherAnchor = { ...anchor, anchor_id: "src-other" };
  const result = caseAgentEvidencePresentation({
    summary: "source-bound summary",
    supported_claims: [{ claim: "source-bound claim" }],
    unknowns: ["product reachability"],
    citation_review: { state: "unverified_model_advice", citations: [{ quote: "fixed text" }] },
    model_suggestions: [
      { text: "review the caller", source_anchor: anchor, semantic_support: "unverified_by_machine" },
      { text: "other candidate advice", source_anchor: otherAnchor },
    ],
  }, anchor);
  assert.equal(result.available, true);
  assert.equal(result.summary, "source-bound summary");
  assert.deepEqual(result.supportedClaims, [{ claim: "source-bound claim" }]);
  assert.deepEqual(result.unknowns, ["product reachability"]);
  assert.equal(result.modelSuggestions.length, 1);
  assert.equal(result.modelSuggestions[0].semantic_support, "unverified_by_machine");
});

test("case UI requires matching fixed source anchor for remediation drafts and PoC plans", () => {
  const draft = {
    state: "draft_unverified",
    draft: "validate bounds before writing",
    source_anchor: anchor,
    provenance: "generic CWE draft",
    review_checks: ["review patch"],
  };
  assert.equal(caseRemediationDraftPresentation(draft, anchor).available, true);
  assert.equal(caseRemediationDraftPresentation({ ...draft, source_anchor: { ...anchor, source_sha256: "c".repeat(64) } }, anchor).available, false);

  const plan = {
    state: "plan_only",
    execution: { requested: false, queued: false, executed: false },
    steps: [{ id: "review_entry", action: "review fixed source", source_anchor: anchor }],
  };
  assert.equal(casePocPlanPresentation(plan, anchor).available, true);
  assert.equal(casePocPlanPresentation({ ...plan, execution: { ...plan.execution, queued: true } }, anchor).available, false);
  assert.equal(casePocPlanPresentation({ ...plan, steps: [{ ...plan.steps[0], source_anchor: { ...anchor, commit: "c".repeat(40) } }] }, anchor).available, false);
});
