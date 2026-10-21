const SHA256_RE = /^[0-9a-f]{64}$/;

function isVerifiedAnchor(anchor) {
  return anchor?.verified === true
    && typeof anchor.anchor_id === "string"
    && typeof anchor.commit === "string"
    && typeof anchor.source_sha256 === "string"
    && SHA256_RE.test(anchor.source_sha256);
}

function sameAnchor(left, right) {
  return isVerifiedAnchor(left) && isVerifiedAnchor(right)
    && left.anchor_id === right.anchor_id
    && left.commit === right.commit
    && left.source_sha256 === right.source_sha256;
}

export function caseAgentEvidencePresentation(triage, sourceAnchor) {
  const citations = triage?.citation_review?.citations;
  const available = triage?.citation_review?.state === "unverified_model_advice"
    && isVerifiedAnchor(sourceAnchor)
    && Array.isArray(citations) && citations.length > 0;
  const suggestions = available && Array.isArray(triage?.model_suggestions)
    ? triage.model_suggestions.filter((item) => sameAnchor(item?.source_anchor, sourceAnchor))
    : [];
  return {
    available,
    summary: available && typeof triage.summary === "string" ? triage.summary : "",
    supportedClaims: available && Array.isArray(triage.supported_claims) ? triage.supported_claims : [],
    unknowns: available && Array.isArray(triage.unknowns) ? triage.unknowns : [],
    modelSuggestions: suggestions,
  };
}

export function caseRemediationDraftPresentation(draft, sourceAnchor) {
  const available = draft?.state === "draft_unverified"
    && typeof draft.draft === "string" && draft.draft.trim().length > 0
    && sameAnchor(draft.source_anchor, sourceAnchor);
  return available
    ? { available: true, draft: draft.draft, provenance: draft.provenance || "未提供来源",
      aiBasis: draft.ai_basis || { state: "unknown", citations: [], note: "没有可核验的 AI 来源。" },
      reviewChecks: Array.isArray(draft.review_checks) ? draft.review_checks : [] }
    : { available: false, reason: draft?.reason || "固定源码锚点未通过核验。" };
}

export function casePocPlanPresentation(plan, sourceAnchor) {
  const execution = plan?.execution;
  const steps = Array.isArray(plan?.steps) ? plan.steps : [];
  const available = plan?.state === "plan_only"
    && execution?.requested === false && execution?.queued === false && execution?.executed === false
    && isVerifiedAnchor(sourceAnchor) && steps.length > 0
    && steps.every((step) => typeof step.action === "string" && step.action.trim().length > 0
      && sameAnchor(step.source_anchor, sourceAnchor));
  return available
    ? { available: true, steps, authorization: plan.authorization || "仅为计划，未执行。" }
    : { available: false, reason: plan?.reason || "计划或固定源码证据材料不足。" };
}
