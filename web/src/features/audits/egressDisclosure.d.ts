export function redactionNotice(preview?: any): string;
export function disclosureReviewed(openKeys: Array<string | number>, requiredKeys: Array<string | number>): boolean;
export function disclosureSelectionMatches(selectedKeys: Array<string | number>, previewKeys: Array<string | number>): boolean;

export function canApproveSourceSubmission(input: { ready: boolean; preview: any; disclosureOpened: boolean }): boolean;
export function canCreateAgentInvestigation(input: { ready: boolean; jobId?: string; candidateId?: string; preview: any; disclosureOpened: boolean; approved: boolean }): boolean;
