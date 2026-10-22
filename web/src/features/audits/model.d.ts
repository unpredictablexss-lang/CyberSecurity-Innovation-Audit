export function auditWorkflowLabel(plan: any, auditMode?: string): string;
export function defaultRepositoryRevision(refs: any[]): string;
export function approvedDetectorIds(detectors: any[], explicitIds?: string[]): string[];
export function researchDetectorIds(detectors: any[]): string[];
export function includePaths(value?: unknown): string[];
export function snapshotPayload(values: any, detectors: any[], explicitIds?: string[]): any;
export function datePreviewPayload(values: any): any;
export function operationPayload(kind: string, values: any, detectors: any[], explicitIds?: string[]): any;
export function recentRange(days: number, timezone: string, now?: Date): { start: string; end: string };
export function localDateTime(date: Date, timezone: string): string;
export function requestGate(): { next(): number; invalidate(): void; current(id: number): boolean };

export function planPayload(values: any, detectors: any[], explicitIds?: string[]): any;
export function taskAuthorizationPayload(values: any): { auto_triage: boolean };
export function auditErrorMessage(error: unknown): string;
export function selectedAuditModeValues(values: any): any;

export function candidateBatchLimit(policy: any, mode: string): number | null;
export function isTimeRangeOperation(operation: any): boolean;
