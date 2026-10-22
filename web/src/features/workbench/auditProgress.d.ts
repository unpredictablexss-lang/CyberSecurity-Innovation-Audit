export interface AuditPhaseProgress {
  label: string; total: number; completed: number; limited: number; running: number; queued: number;
  failed: number; blocked: number; interrupted: number; cancelled: number; text: string;
}
export function isIntelligentAudit(job: any): boolean;
export function auditProgress(job: any, summary?: any): {
  label: string; color: string; poll: boolean; phases: AuditPhaseProgress[]; active: boolean;
};
