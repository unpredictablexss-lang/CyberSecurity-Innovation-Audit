export function disclosedCves(item: any): string[];
export function prioritizeDisclosedCves<T>(items: T[]): T[];
export function prioritizeWithRiskEvidence<T>(items: T[], riskItems: any[]): T[];
export function loadCandidatePages(request: (path: string) => Promise<any>, path: string): Promise<any>;
