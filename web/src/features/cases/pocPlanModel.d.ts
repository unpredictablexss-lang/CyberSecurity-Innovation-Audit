export interface PocPlanCandidateRow {
  repository?: string;
  commit?: string;
  report_sha256?: string;
  candidate?: {
    id?: string;
    file?: string;
    line?: number;
    source_sha256?: string;
    evidence_obligations?: unknown[];
  };
  source_evidence?: unknown[];
}

export interface PocValidationPlan {
  title: string;
  executionStatus: "not_executed";
  findingState: "candidate / unknown";
  sourceBinding: Record<string, string | number | null>;
  sourceBindingComplete: boolean;
  bindingMissing: string[];
  bindingMissingLabels: string[];
  obligations: Array<Record<string, string | number>>;
  sourceEvidence: Array<Record<string, string | number | null>>;
  matchingAgentOperationIds: string[];
  validationContext: Array<Record<string, string | boolean>>;
  sections: Array<{ title: string; detail: string }>;
  unknowns: string[];
  generatedExecutable: false;
  executed: false;
}

export function buildPocValidationPlan(
  candidateRow?: PocPlanCandidateRow,
  operations?: unknown[],
): PocValidationPlan;
