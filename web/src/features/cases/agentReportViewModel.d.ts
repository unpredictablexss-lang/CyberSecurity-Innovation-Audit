export interface AgentReportCitationView {
  displayText: string;
  evidenceId: string;
  location: string;
  quote: string;
  raw: unknown;
}

export interface AgentVulnerabilityReportView {
  title: string;
  summary: string;
  rootCause: string;
  impact: string;
  preconditions: string[];
  attackPath: string[];
  remediation: string;
  citations: AgentReportCitationView[];
  boundary: string;
}

export interface AgentPocDraftView {
  status: string;
  statusLabel: string;
  title: string;
  language: string;
  code: string;
  prerequisites: string[];
  runSteps: string[];
  expectedObservation: string;
  negativeControl: string;
  citations: AgentReportCitationView[];
  boundary: string;
}

export interface AgentArtifactGenerationView {
  status: string;
  statusLabel: string;
  reportStatusLabel: string;
  pocStatusLabel: string;
  callsUsed: number | null;
  maximumModelCalls: number | null;
}

export function buildAgentReportView(agentTriage?: unknown): {
  vulnerabilityReport: AgentVulnerabilityReportView | null;
  pocDraft: AgentPocDraftView | null;
  artifactGeneration: AgentArtifactGenerationView | null;
}

export function buildAgentOperationArtifactView(operationResult?: unknown): {
  vulnerabilityReport: AgentVulnerabilityReportView | null;
  pocDraft: AgentPocDraftView | null;
  artifactGeneration: AgentArtifactGenerationView | null;
}
