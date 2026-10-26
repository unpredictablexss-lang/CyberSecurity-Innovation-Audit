export interface QuickScreenPresentation {
  assessment: string;
  reviewStatus: string;
  requestState: string;
  rationale: string;
  missingEvidence: string;
  nextSteps: string;
  uncertainties: string;
  budgetState: string;
  hasEnglishOriginal: boolean;
}

export function quickScreenPresentation(
  result?: Record<string, any>,
  requestState?: string,
): QuickScreenPresentation;
export function quickAssessmentLabel(value: string): string;
export function quickScreenStateLabel(value: string): string;
export function modelReviewStatusLabel(value: string): string;
export function budgetStateLabel(value: string): string;
export function investigationStopReasonLabel(value: string): string;
export function budgetEnforcementLabel(value: string): string;
