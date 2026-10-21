export function buildEvidenceGraphView(value: unknown): {
  binding: { repository: string; commit: string; candidateId: string };
  stages: Array<{
    id: string;
    label: string;
    status: string;
    statusLabel: string;
    epistemicStatus: string;
  }>;
  evidence: Array<{
    id: string;
    evidenceId: string;
    kind: string;
    status: string;
    locations: Array<{
      file: string;
      line: number | null;
      endLine: number | null;
      label: string;
      status: string;
    }>;
  }>;
  citations: Array<{
    id: string;
    type: string;
    label: string;
    stageLabel: string;
    evidenceId: string;
    file: string;
    line: number | null;
    endLine: number | null;
    location: string;
    semanticSupport: string;
  }>;
  unresolved: Array<{ stageLabel: string; file: string; reason: string }>;
  complete: boolean;
  statusLabel: string;
  boundary: string;
  productState: string;
  validatedVulnerability: number;
} | null;
