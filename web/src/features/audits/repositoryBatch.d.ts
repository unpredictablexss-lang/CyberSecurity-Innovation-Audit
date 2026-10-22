export function repositoryAuditEntries(values: any, repositories: any[], detectors: any[]): any[];
export function prepareRepositoryAudits(entries: any[], request: (path: string, body: any) => Promise<any>, progress?: (index: number, total: number, name: string) => void, current?: () => boolean): Promise<any[] | null>;
export function repositoryScanRequest(entry: any): any;
export function repositoryBatchConsent(entries: any[]): any;
export function createRepositoryAudits(entries: any[], request: (path: string, body: any) => Promise<any>, progress?: (row: any) => void): Promise<any[]>;
