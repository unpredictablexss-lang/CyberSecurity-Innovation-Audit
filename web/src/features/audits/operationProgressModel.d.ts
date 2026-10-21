export type ReviewPhaseView = {
  state: string;
  stateLabel: string;
  operationCount: number | null;
  summariesReturned: boolean;
  counts: Record<"queued" | "running" | "completed" | "failed" | "cancelled" | "timed_out" | "interrupted" | "blocked", number>;
  reasons: Array<{ operationId: string | null; candidateId: string | null; status: string; statusLabel: string; reason: string }>;
  operations: Array<{ id: string | null; status: string; statusLabel: string; commit: string | null; candidateId: string | null; resultSha256: string | null; reportSha256: string | null; bindingValid: boolean; bindingIssue: string | null }>;
};
export const JOINT_CANDIDATE_PREVIEW_PATH: "/operations/version-matrix-candidate-comparisons/preview";
export const JOINT_CANDIDATE_CREATE_PATH: "/operations/version-matrix-candidate-comparisons";
export function buildIntelligentReviewView(endpoint: any): null | {
  state: string; stateLabel: string; stateTone: "success" | "warning" | "error" | "default";
  reason: string | null; candidateCount: number | null; commit: string | null; scanId: string | null;
  r1: ReviewPhaseView; r2: ReviewPhaseView; isStatic: boolean; modelResultIsConfirmation: boolean;
};
export function buildMatrixCandidatePairs(operation: any): Array<{
  key: string; fromCommit: string | null; toCommit: string | null; status: string; matchBasis: string;
  file: string; detectorId: string; ruleId: string; fromCandidate: any; toCandidate: any; eligibleForPreview: boolean;
}>;
export function jointCandidatePreviewPayload(matrixOperationId: string, pair: any): {
  matrix_operation_id: string; from_commit: string; from_candidate_id: string; to_commit: string; to_candidate_id: string;
};
export function jointCandidateCreatePayload(matrixOperationId: string, pair: any, consent: any): {
  matrix_operation_id: string; from_commit: string; from_candidate_id: string; to_commit: string; to_candidate_id: string;
  approved: true; consent_nonce: string; expected_consent_sha256: string; expires_at: string;
};
export function buildJointLinkedAgentChildrenView(contextSummary: any): {
  resultCount: number | null;
  from: { provided: boolean; items: Array<{ id: string | null; status: string; statusLabel: string; resultSha256: string | null; bindingIssue: string | null; linkValid: boolean }> };
  to: { provided: boolean; items: Array<{ id: string | null; status: string; statusLabel: string; resultSha256: string | null; bindingIssue: string | null; linkValid: boolean }> };
};
export function buildJointEgressSummary(contextSummary: any): { evidenceProvided: boolean; evidenceCount: number | null; sourceEvidenceCount: number | null; fileCount: number | null; linkedReviewProvided: boolean; linkedReviewCount: number | null; linkedReviewFromCount: number | null; linkedReviewToCount: number | null };
