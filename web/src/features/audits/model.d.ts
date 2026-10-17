export function approvedDetectorIds(detectors: any[]): string[];
export function includePaths(value?: unknown): string[];
export function snapshotPayload(values: any, detectors: any[]): any;
export function datePreviewPayload(values: any): any;
export function operationPayload(kind: string, values: any, detectors: any[]): any;
export function recentRange(days: number, timezone: string, now?: Date): { start: string; end: string };
export function localDateTime(date: Date, timezone: string): string;
export function requestGate(): { next(): number; invalidate(): void; current(id: number): boolean };

export function planPayload(values: any, detectors: any[]): any;
