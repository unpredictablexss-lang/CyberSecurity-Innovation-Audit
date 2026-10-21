export type CaseSourceAnchor = {
  verified?: boolean;
  anchor_id?: string;
  commit?: string;
  source_sha256?: string;
  [key: string]: unknown;
};

export function caseAgentEvidencePresentation(
  triage: Record<string, any> | null | undefined,
  sourceAnchor: CaseSourceAnchor,
): {
  available: boolean;
  summary: string;
  supportedClaims: any[];
  unknowns: string[];
  modelSuggestions: any[];
};

export function caseRemediationDraftPresentation(
  draft: Record<string, any> | null | undefined,
  sourceAnchor: CaseSourceAnchor,
): { available: true; draft: string; provenance: string; aiBasis: Record<string, any>; reviewChecks: string[] }
  | { available: false; reason: string };

export function casePocPlanPresentation(
  plan: Record<string, any> | null | undefined,
  sourceAnchor: CaseSourceAnchor,
): { available: true; steps: any[]; authorization: string }
  | { available: false; reason: string };
